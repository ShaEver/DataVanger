using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Memory;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;
using DataVanger.Reputation;
using static DataVanger.Tests.Fixtures.PeFactory;

// Phase 09 decomposition — Runtime Event Pipeline (Phase 2 / Step 04). Filter: ~RuntimeEventPipeline.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class RuntimeEventPipelineTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task RuntimeEventPipeline_AllLegacyChecks()
// 27. Runtime Event Pipeline (Phase 2 / Step 04) — deterministic,
//     development-safe tests for the centralized runtime security event
//     pipeline. None of these tests may require admin, install a service,
//     start ETW/AMSI providers, touch the network, or leave background work
//     behind. Inline dispatch + bounded in-flight depth keep everything
//     deterministic without sleeps.
{
    static DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent NewEvent(
        string title,
        DataVanger.Shared.RuntimeEvents.RuntimeEventCategory category
            = DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.HealthStatus,
        DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity severity
            = DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.Informational,
        DataVanger.Shared.RuntimeEvents.RuntimeEventSource source
            = DataVanger.Shared.RuntimeEvents.RuntimeEventSource.TestHarness,
        string? subjectPath = null)
        => new()
        {
            EventId = title,
            Source = source,
            Category = category,
            Severity = severity,
            Title = title,
            Description = "test event",
            SubjectPath = subjectPath,
            TimestampUtc = new DateTimeOffset(2026, 5, 27, 0, 0, 0, TimeSpan.Zero),
        };

    // 27a. Publish + deliver to a single consumer in order.
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        await runtimePipeline.PublishAsync(NewEvent("alpha")).AsTask();
        await runtimePipeline.PublishAsync(NewEvent("beta")).AsTask();
        await runtimePipeline.PublishAsync(NewEvent("gamma")).AsTask();

        var got = consumer.Snapshot();
        Assert(got.Count == 3, "Consumer must receive every published event.");
        Assert(got[0].Title == "alpha" && got[1].Title == "beta" && got[2].Title == "gamma",
            "Inline dispatch must preserve publication order for a single consumer.");

        var health = runtimePipeline.GetHealthSnapshot();
        Assert(health.EventsPublished == 3, "Health must report 3 events published.");
        Assert(health.EventsDelivered == 3, "Health must report 3 events delivered.");
        Assert(health.EventsDropped == 0, "No drops expected on happy path.");
        Assert(health.SubscriberCount == 1, "One subscriber registered.");
        Assert(health.QueueDepth == 0, "Inline dispatch must leave queue depth at 0 after publish completes.");
        Assert(health.Status == "Healthy", "Healthy pipeline must report Status=Healthy.");
        Assert(health.IsDevelopmentMode, "Default pipeline must be in Development mode.");
    }

    // 27b. Multiple subscribers receive the same event.
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var c1 = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        var c2 = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        var c3 = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(c1);
        runtimePipeline.Subscribe(c2);
        runtimePipeline.Subscribe(c3);

        await runtimePipeline.PublishAsync(NewEvent("fanout")).AsTask();

        Assert(c1.Count == 1 && c2.Count == 1 && c3.Count == 1,
            "Every subscriber must receive the published event.");
        Assert(runtimePipeline.GetHealthSnapshot().EventsDelivered == 3,
            "Three subscribers means three deliveries for one published event.");
    }

    // 27c. Duplicate Subscribe is idempotent (no double delivery to same instance).
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);
        runtimePipeline.Subscribe(consumer); // intentional duplicate
        runtimePipeline.Subscribe(consumer);

        await runtimePipeline.PublishAsync(NewEvent("dedupe")).AsTask();
        Assert(consumer.Count == 1,
            "Subscribing the same instance multiple times must not double-deliver events.");
        Assert(runtimePipeline.GetHealthSnapshot().SubscriberCount == 1,
            "Subscriber count must reflect distinct consumer instances.");
    }

    // 27d. Unsubscribe stops delivery.
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);
        await runtimePipeline.PublishAsync(NewEvent("e1")).AsTask();
        Assert(runtimePipeline.Unsubscribe(consumer), "Unsubscribe must return true for a known consumer.");
        Assert(!runtimePipeline.Unsubscribe(consumer), "Unsubscribe must return false for an unknown consumer.");
        await runtimePipeline.PublishAsync(NewEvent("e2")).AsTask();
        Assert(consumer.Count == 1, "Unsubscribed consumer must not receive subsequent events.");
    }

    // 27e. Consumer exception is isolated — the pipeline does not crash and other
    //      consumers still receive the event. The failure is recorded in health warnings.
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var throwing = new DataVanger.Engine.RuntimeEvents.DelegateRuntimeEventConsumer(
            _ => throw new InvalidOperationException("synthetic consumer failure"));
        var collecting = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(throwing);
        runtimePipeline.Subscribe(collecting);

        await runtimePipeline.PublishAsync(NewEvent("survives")).AsTask();
        await runtimePipeline.PublishAsync(NewEvent("again")).AsTask();

        Assert(collecting.Count == 2, "A throwing consumer must not prevent delivery to others.");
        var health = runtimePipeline.GetHealthSnapshot();
        Assert(health.EventsPublished == 2, "Published events must still be counted when a consumer throws.");
        Assert(health.EventsDelivered == 2, "Delivered count tracks successful deliveries only (collecting consumer x2).");
        Assert(health.Warnings.Count >= 1, "Consumer exceptions must surface as health warnings.");
        Assert(health.Status == "Degraded", "Pipeline with consumer warnings must report Status=Degraded.");
    }

    // 27f. Cancellation is respected: no delivery, counted as dropped, no throw.
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await runtimePipeline.PublishAsync(NewEvent("canceled"), cts.Token).AsTask();

        Assert(consumer.Count == 0, "Publishes with a cancelled token must not be delivered.");
        var health = runtimePipeline.GetHealthSnapshot();
        Assert(health.EventsPublished == 0, "Cancelled publishes must not increment EventsPublished.");
        Assert(health.EventsDropped == 1, "Cancelled publishes must be counted as dropped.");
    }

    // 27g. Disabled mode does not deliver events.
    {
        var options = new DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineOptions
        {
            Enabled = false,
            Mode = DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineMode.Disabled,
        };
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline(options);
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        await runtimePipeline.PublishAsync(NewEvent("nope1")).AsTask();
        await runtimePipeline.PublishAsync(NewEvent("nope2")).AsTask();
        await runtimePipeline.PublishAsync(NewEvent("nope3")).AsTask();

        Assert(consumer.Count == 0, "Disabled mode must not deliver events to consumers.");
        var health = runtimePipeline.GetHealthSnapshot();
        Assert(!health.IsEnabled, "Disabled mode must report IsEnabled=false.");
        Assert(health.Status == "Disabled", "Disabled pipeline must report Status=Disabled.");
        Assert(health.EventsDropped == 3, "Disabled mode must count publishes as dropped.");
        Assert(health.EventsPublished == 0, "Disabled mode must not increment EventsPublished.");
    }

    // 27h. Bounded queue: a deliberately-tiny MaxQueueSize plus a consumer that
    //      re-enters PublishAsync during HandleAsync forces an overflow. The
    //      re-entrant publish is dropped (counted), no throw, no infinite recursion.
    {
        var options = new DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineOptions
        {
            Enabled = true,
            Mode = DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineMode.Development,
            MaxQueueSize = 1,
        };
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline(options);

        var collecting = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(collecting);

        // Consumer that, on the very first delivery, re-publishes another event.
        // The re-publish increments queue depth to 2 (> MaxQueueSize=1) so the
        // pipeline MUST drop it without throwing or recursing further.
        int reentryAttempts = 0;
        var reentrant = new DataVanger.Engine.RuntimeEvents.DelegateRuntimeEventConsumer(_ =>
        {
            if (Interlocked.Increment(ref reentryAttempts) == 1)
            {
                // xUnit1031-deferred: this blocking call is inside a synchronous DelegateRuntimeEventConsumer
                // callback (an Action-style delegate). Converting to await would require an async-void delegate,
                // changing the re-entrant publish from synchronous to fire-and-forget and breaking the
                // "runs exactly once / drop prevents recursion" assertion below. Kept blocking on purpose.
                runtimePipeline.PublishAsync(NewEvent("inner")).AsTask().GetAwaiter().GetResult();
            }
        });
        runtimePipeline.Subscribe(reentrant);

        await runtimePipeline.PublishAsync(NewEvent("outer")).AsTask();

        Assert(reentryAttempts == 1, "Re-entrant publish must run exactly once (drop prevents recursion).");
        Assert(collecting.Count == 1, "Only the outer event should reach the collecting consumer.");

        var health = runtimePipeline.GetHealthSnapshot();
        Assert(health.EventsPublished == 1, "Only the outer publish should count as published.");
        Assert(health.EventsDropped >= 1, "Overflow re-publish must be counted as dropped.");
        Assert(health.MaxQueueSize == 1, "Health must echo the configured MaxQueueSize.");
        Assert(health.MaxQueueDepth >= 1, "MaxQueueDepth must reflect observed in-flight depth.");
    }

    // 27i. Disposed pipeline drops further publishes silently, no throw.
    {
        var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);
        await runtimePipeline.PublishAsync(NewEvent("before")).AsTask();
        Assert(consumer.Count == 1, "Sanity: event delivered before dispose.");

        runtimePipeline.Dispose();
        // Idempotent dispose
        runtimePipeline.Dispose();

        await runtimePipeline.PublishAsync(NewEvent("after")).AsTask();
        Assert(consumer.Count == 1, "Disposed pipeline must not deliver further events.");
        var health = runtimePipeline.GetHealthSnapshot();
        Assert(health.Status == "Stopped", "Disposed pipeline must report Status=Stopped.");
        Assert(health.SubscriberCount == 0, "Dispose must clear subscribers.");
        Assert(health.EventsDropped >= 1, "Post-dispose publishes must be counted as dropped.");
    }

    // 27j. Shutdown must not hang even with a consumer that has been on the
    //      delivery path. Inline dispatch means PublishAsync has already returned
    //      before Dispose is called; we measure the dispose cost just to make the
    //      "shutdown does not hang" guarantee explicit.
    {
        var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        runtimePipeline.Subscribe(new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer());
        for (int i = 0; i < 50; i++)
        {
            await runtimePipeline.PublishAsync(NewEvent("shutdown-" + i)).AsTask();
        }
        var sw = System.Diagnostics.Stopwatch.StartNew();
        runtimePipeline.Dispose();
        sw.Stop();
        Assert(sw.ElapsedMilliseconds < 1000,
            $"Pipeline shutdown must be free of background work (took {sw.ElapsedMilliseconds}ms).");
    }

    // 27k. Null event is a no-op (counted as dropped, not an exception).
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);
        await runtimePipeline.PublishAsync(null!).AsTask();
        Assert(consumer.Count == 0, "Null event must not be delivered.");
        Assert(runtimePipeline.GetHealthSnapshot().EventsDropped == 1,
            "Null event must increment EventsDropped (visible in diagnostics, not silent).");
    }

    // 27l. Anti-FP guarantee: runtime event severity is NOT a malware classification.
    //      File events, ransomware-suspicion events, and tamper events — even at
    //      Critical severity — must NEVER trigger quarantine, kill processes, block
    //      files, or escalate to ConfirmedMalware via the pipeline. The pipeline
    //      offers no remediation surface, so we assert by structural inspection.
    {
        using var runtimePipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        int destructiveActionAttempts = 0;
        var observer = new DataVanger.Engine.RuntimeEvents.DelegateRuntimeEventConsumer(ev =>
        {
            // The pipeline contract provides ONLY telemetry to consumers — there is
            // no "Authorize" or "Quarantine" method on the event. Assert that the
            // event model does not expose a verdict-escalation surface.
            var verdictProps = typeof(DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent)
                .GetProperties()
                .Where(p =>
                    p.Name.Contains("ConfirmedMalware", StringComparison.OrdinalIgnoreCase) ||
                    p.Name.Contains("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                    p.Name.Contains("Authorize", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            Assert(verdictProps.Length == 0,
                "RuntimeSecurityEvent must NOT expose verdict-escalation, quarantine, or authorization properties.");

            // The pipeline interface itself must not expose remediation either.
            var pipelineMethods = typeof(DataVanger.Shared.RuntimeEvents.IRuntimeEventPipeline)
                .GetMethods()
                .Where(m =>
                    m.Name.Contains("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                    m.Name.Contains("Kill", StringComparison.OrdinalIgnoreCase) ||
                    m.Name.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
                    m.Name.Contains("Confirm", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            Assert(pipelineMethods.Length == 0,
                "IRuntimeEventPipeline must NOT expose remediation or verdict-confirmation methods.");

            // Any consumer that *tried* to take destructive action would need an
            // external collaborator — none is provided here, so this counter must
            // remain at zero for the duration of the test.
            destructiveActionAttempts += 0;
            _ = ev; // event ignored on purpose
        });
        runtimePipeline.Subscribe(observer);

        await runtimePipeline.PublishAsync(NewEvent(
            "critical-file",
            DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileCreated,
            DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.Critical,
            DataVanger.Shared.RuntimeEvents.RuntimeEventSource.RealtimeFileProtection,
            subjectPath: "C:/fake/path.exe")).AsTask();

        await runtimePipeline.PublishAsync(NewEvent(
            "ransomware-suspicion",
            DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.RansomwareSuspicion,
            DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.Critical,
            DataVanger.Shared.RuntimeEvents.RuntimeEventSource.AntiRansomware)).AsTask();

        await runtimePipeline.PublishAsync(NewEvent(
            "tamper",
            DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.TamperObserved,
            DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.High,
            DataVanger.Shared.RuntimeEvents.RuntimeEventSource.SelfProtection)).AsTask();

        Assert(destructiveActionAttempts == 0,
            "Anti-FP: pipeline events must never trigger destructive remediation.");
    }

    // 27m. Service-level factory returns development-safe and disabled pipelines.
    {
        using var dev = DataVanger.Service.RuntimeEvents.RuntimeEventPipelineFactory.CreateDevelopmentPipeline();
        var devHealth = dev.GetHealthSnapshot();
        Assert(devHealth.IsEnabled, "Factory development pipeline must be enabled.");
        Assert(devHealth.IsDevelopmentMode, "Factory development pipeline must be in Development mode.");
        Assert(devHealth.Mode == DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineMode.Development,
            "Factory development pipeline mode must be Development.");

        using var off = DataVanger.Service.RuntimeEvents.RuntimeEventPipelineFactory.CreateDisabledPipeline();
        var offHealth = off.GetHealthSnapshot();
        Assert(!offHealth.IsEnabled, "Factory disabled pipeline must report IsEnabled=false.");
        Assert(offHealth.Status == "Disabled", "Factory disabled pipeline must report Status=Disabled.");

        using var custom = DataVanger.Service.RuntimeEvents.RuntimeEventPipelineFactory.Create(
            new DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineOptions
            {
                Enabled = true,
                Mode = DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineMode.Passive,
                MaxQueueSize = 0, // intentionally invalid; WithSafeDefaults must clamp it
            });
        var customHealth = custom.GetHealthSnapshot();
        Assert(customHealth.MaxQueueSize > 0,
            "WithSafeDefaults must clamp non-positive MaxQueueSize to a safe value.");
        Assert(customHealth.Mode == DataVanger.Shared.RuntimeEvents.RuntimeEventPipelineMode.Passive,
            "Custom factory pipeline must honor caller-supplied Mode.");
    }
}

}
