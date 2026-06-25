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

// Phase 09 decomposition — Advanced Scheduler (deterministic orchestration/persistence/safety). Filter: ~Scheduler.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class SchedulerTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task AdvancedScheduler_AllLegacyChecks()
// 21. Advanced Scheduler — deterministic orchestration, persistence and safety.
{
    static string TempDir(string suffix)
    {
        var p = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "datavanger_sched_" + Guid.NewGuid().ToString("N").Substring(0, 8) + "_" + suffix);
        System.IO.Directory.CreateDirectory(p);
        return p;
    }

    // 21a. ScheduleTrigger — recurrence math is total and deterministic.
    var daily = new DataVanger.Scheduling.Models.ScheduleTrigger
    {
        Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.Daily,
        StartUtc = new DateTime(2025, 6, 1, 8, 0, 0, DateTimeKind.Utc),
    };
    var dailyNext = daily.ComputeNextRunUtc(new DateTime(2025, 6, 1, 7, 0, 0, DateTimeKind.Utc), null);
    Assert(dailyNext == new DateTime(2025, 6, 1, 8, 0, 0, DateTimeKind.Utc),
        "Daily trigger must fire today if anchor time has not passed yet.");
    var dailyAfter = daily.ComputeNextRunUtc(new DateTime(2025, 6, 1, 9, 0, 0, DateTimeKind.Utc), null);
    Assert(dailyAfter == new DateTime(2025, 6, 2, 8, 0, 0, DateTimeKind.Utc),
        "Daily trigger must roll over to next day after the anchor time has passed.");

    var weekly = new DataVanger.Scheduling.Models.ScheduleTrigger
    {
        Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.Weekly,
        StartUtc = new DateTime(2025, 6, 1, 8, 0, 0, DateTimeKind.Utc), // 2025-06-01 is Sunday
        DaysOfWeek = new List<DayOfWeek> { DayOfWeek.Monday, DayOfWeek.Wednesday },
    };
    var weeklyNext = weekly.ComputeNextRunUtc(new DateTime(2025, 6, 1, 9, 0, 0, DateTimeKind.Utc), null);
    Assert(weeklyNext == new DateTime(2025, 6, 2, 8, 0, 0, DateTimeKind.Utc),
        "Weekly trigger must pick the next selected weekday after the cursor.");

    var interval = new DataVanger.Scheduling.Models.ScheduleTrigger
    {
        Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.Interval,
        StartUtc = new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc),
        Interval = TimeSpan.FromHours(2),
    };
    var intervalNext = interval.ComputeNextRunUtc(new DateTime(2025, 6, 1, 5, 30, 0, DateTimeKind.Utc), null);
    Assert(intervalNext == new DateTime(2025, 6, 1, 6, 0, 0, DateTimeKind.Utc),
        "Interval trigger must snap forward to the next slot strictly after the cursor.");

    var oneTime = new DataVanger.Scheduling.Models.ScheduleTrigger
    {
        Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.OneTime,
        StartUtc = new DateTime(2025, 6, 1, 10, 0, 0, DateTimeKind.Utc),
    };
    Assert(oneTime.ComputeNextRunUtc(DateTime.UtcNow, lastRunUtc: new DateTime(2025, 6, 1, 10, 0, 0, DateTimeKind.Utc)) == null,
        "OneTime trigger must not fire again once it has a last-run timestamp.");

    // 21b. JsonSchedulerStore — corrupted scheduler data must degrade gracefully.
    var corruptDir = TempDir("corrupt");
    System.IO.File.WriteAllText(System.IO.Path.Combine(corruptDir, "scheduler_jobs.json"), "{this is not valid json");
    System.IO.File.WriteAllText(System.IO.Path.Combine(corruptDir, "scheduler_status.json"), "garbled");
    System.IO.File.WriteAllText(System.IO.Path.Combine(corruptDir, "scheduler_history.json"), "<<<corrupt>>>");
    var corruptStore = new DataVanger.Scheduling.JsonSchedulerStore(corruptDir);
    Assert(corruptStore.LoadJobs().Count == 0
        && corruptStore.LoadStatus().Count == 0
        && corruptStore.LoadHistory().Count == 0,
        "JsonSchedulerStore must return empty lists for corrupted scheduler payloads, never throw.");

    // Malformed entries should not crash the orchestrator either.
    var malformedSchedule = new DataVanger.Scheduling.Models.ScheduledJobDefinition
    {
        Id = "", // sanitized on AddOrUpdate
        Name = "broken",
        Trigger = null!,
        Retry = null!,
    };

    // 21c. Deterministic clock-driven execution.
    var clock = new DataVanger.Scheduling.FakeClock(new DateTime(2025, 6, 1, 7, 59, 0, DateTimeKind.Utc));
    var storeDir = TempDir("happy");
    var store = new DataVanger.Scheduling.JsonSchedulerStore(storeDir);
    var runner = new FakeScheduledRunner();
    var scheduler = new DataVanger.Scheduling.ScanScheduler(clock, store, runner);

    var job = new DataVanger.Scheduling.Models.ScheduledJobDefinition
    {
        Id = "job-1",
        Name = "Daily quick",
        Profile = DataVanger.Core.ScanProfile.Fast,
        Trigger = new DataVanger.Scheduling.Models.ScheduleTrigger
        {
            Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.Daily,
            StartUtc = new DateTime(2025, 6, 1, 8, 0, 0, DateTimeKind.Utc),
        },
    };
    scheduler.AddOrUpdate(job);
    scheduler.AddOrUpdate(malformedSchedule); // must not throw even with null trigger/retry.

    // Not due yet.
    var none = await scheduler.ProcessDueAsync();
    Assert(none.Count == 0,
        "ProcessDueAsync must skip jobs whose NextRunUtc has not arrived yet.");

    // Advance past anchor — job becomes due.
    clock.Advance(TimeSpan.FromMinutes(2));
    var dueExecs = await scheduler.ProcessDueAsync();
    Assert(dueExecs.Count == 1
        && dueExecs[0].Outcome == DataVanger.Scheduling.Models.JobRunOutcome.Success
        && runner.LastRunJobId == "job-1",
        "ProcessDueAsync must execute due jobs and record a Success outcome.");
    Assert(runner.LastRunProfile == DataVanger.Core.ScanProfile.Fast,
        "Scheduled runner must receive the job's scan profile unchanged.");

    var statusAfter = scheduler.GetStatus("job-1")!;
    Assert(statusAfter.LastOutcome == DataVanger.Scheduling.Models.JobRunOutcome.Success
        && statusAfter.NextRunUtc.HasValue
        && statusAfter.NextRunUtc.Value > clock.UtcNow,
        "After a successful run NextRunUtc must advance into the future.");

    Assert(store.LoadHistory().Count >= 1,
        "Scheduler history must persist completed runs.");

    // 21d. Re-entrant call before next slot must yield nothing (no duplicate execution).
    var rerun = await scheduler.ProcessDueAsync();
    Assert(rerun.Count == 0,
        "ProcessDueAsync must not re-fire a recurring job before its next slot.");

    // 21e. Pause/Resume.
    scheduler.Pause();
    clock.Advance(TimeSpan.FromDays(2));
    Assert((await scheduler.ProcessDueAsync()).Count == 0,
        "Paused scheduler must not execute any due job.");
    scheduler.Resume();
    var afterResume = await scheduler.ProcessDueAsync();
    Assert(afterResume.Count == 1,
        "Resumed scheduler must process pending due jobs.");

    // 21f. Disabled job must not run.
    scheduler.SetEnabled("job-1", false);
    clock.Advance(TimeSpan.FromDays(5));
    Assert((await scheduler.ProcessDueAsync()).Count == 0,
        "Disabled scheduled jobs must not execute.");
    scheduler.SetEnabled("job-1", true);

    // 21g. Cancellation token honoured.
    using (var cts = new CancellationTokenSource())
    {
        cts.Cancel();
        clock.Advance(TimeSpan.FromDays(2));
        Assert((await scheduler.ProcessDueAsync(cts.Token)).Count == 0,
            "ProcessDueAsync must observe an already-cancelled token.");
    }

    // 21h. Failure -> bounded retry -> no unbounded loop.
    var retryClock = new DataVanger.Scheduling.FakeClock(new DateTime(2025, 7, 1, 0, 0, 0, DateTimeKind.Utc));
    var retryStore = new DataVanger.Scheduling.JsonSchedulerStore(TempDir("retry"));
    var failRunner = new AlwaysFailRunner();
    var retryScheduler = new DataVanger.Scheduling.ScanScheduler(
        retryClock, retryStore, failRunner,
        new DataVanger.Scheduling.SchedulerPolicy { MaxRetryAttemptsCeiling = 3 });
    var retryJob = new DataVanger.Scheduling.Models.ScheduledJobDefinition
    {
        Id = "retry-1",
        Name = "Flaky",
        Trigger = new DataVanger.Scheduling.Models.ScheduleTrigger
        {
            Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.OneTime,
            StartUtc = retryClock.UtcNow,
        },
        Retry = new DataVanger.Scheduling.Models.RetryPolicy { MaxAttempts = 3, BackoffBase = TimeSpan.FromMinutes(1) },
    };
    retryScheduler.AddOrUpdate(retryJob);

    for (int i = 0; i < 10; i++)
    {
        retryClock.Advance(TimeSpan.FromMinutes(30));
        await retryScheduler.ProcessDueAsync();
    }
    Assert(failRunner.Invocations <= 3,
        "Retry policy must cap attempts; an always-failing job must not retry beyond MaxAttempts.");
    var retryStatus = retryScheduler.GetStatus("retry-1")!;
    Assert(retryStatus.ConsecutiveFailures > 0 && retryStatus.PendingRetryUtc == null,
        "After retries exhaust, pending retry must clear and failure counter must persist for telemetry.");

    // 21i. Overlap prevention — only one job runs at a time per default policy.
    var overlapClock = new DataVanger.Scheduling.FakeClock(new DateTime(2025, 8, 1, 0, 0, 0, DateTimeKind.Utc));
    var overlapStore = new DataVanger.Scheduling.JsonSchedulerStore(TempDir("overlap"));
    var overlapRunner = new FakeScheduledRunner();
    var overlapScheduler = new DataVanger.Scheduling.ScanScheduler(overlapClock, overlapStore, overlapRunner);
    for (int i = 0; i < 3; i++)
    {
        overlapScheduler.AddOrUpdate(new DataVanger.Scheduling.Models.ScheduledJobDefinition
        {
            Id = "overlap-" + i,
            Name = "Job " + i,
            Trigger = new DataVanger.Scheduling.Models.ScheduleTrigger
            {
                Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.OneTime,
                StartUtc = overlapClock.UtcNow,
            },
        });
    }
    overlapClock.Advance(TimeSpan.FromSeconds(1));
    var overlapBatch = await overlapScheduler.ProcessDueAsync();
    Assert(overlapBatch.Count == 1,
        "Default scheduler policy must enforce MaxConcurrentJobs=1 per tick to prevent overlap.");

    // 21j. Persistence + recovery — a fresh scheduler instance must restore jobs from disk.
    var persistDir = TempDir("persist");
    var persistStore = new DataVanger.Scheduling.JsonSchedulerStore(persistDir);
    var persistScheduler = new DataVanger.Scheduling.ScanScheduler(
        new DataVanger.Scheduling.FakeClock(new DateTime(2025, 9, 1, 6, 0, 0, DateTimeKind.Utc)),
        persistStore,
        new FakeScheduledRunner());
    persistScheduler.AddOrUpdate(new DataVanger.Scheduling.Models.ScheduledJobDefinition
    {
        Id = "persist-1",
        Name = "Persisted",
        Trigger = new DataVanger.Scheduling.Models.ScheduleTrigger
        {
            Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.Daily,
            StartUtc = new DateTime(2025, 9, 1, 7, 0, 0, DateTimeKind.Utc),
        },
    });
    var revived = new DataVanger.Scheduling.ScanScheduler(
        new DataVanger.Scheduling.FakeClock(new DateTime(2025, 9, 1, 6, 30, 0, DateTimeKind.Utc)),
        new DataVanger.Scheduling.JsonSchedulerStore(persistDir),
        new FakeScheduledRunner());
    Assert(revived.Jobs.Count == 1 && revived.Jobs[0].Id == "persist-1",
        "Scheduler must rehydrate persisted jobs after restart.");

    // 21k. Runner exception is recorded as Failed, never as a malware verdict.
    var throwClock = new DataVanger.Scheduling.FakeClock(new DateTime(2025, 10, 1, 0, 0, 0, DateTimeKind.Utc));
    var throwStore = new DataVanger.Scheduling.JsonSchedulerStore(TempDir("throw"));
    var throwScheduler = new DataVanger.Scheduling.ScanScheduler(
        throwClock, throwStore, new ThrowingScheduledRunner());
    throwScheduler.AddOrUpdate(new DataVanger.Scheduling.Models.ScheduledJobDefinition
    {
        Id = "throw-1",
        Name = "Throws",
        Trigger = new DataVanger.Scheduling.Models.ScheduleTrigger
        {
            Kind = DataVanger.Scheduling.Models.ScheduleTriggerKind.OneTime,
            StartUtc = throwClock.UtcNow,
        },
        Retry = new DataVanger.Scheduling.Models.RetryPolicy { MaxAttempts = 1 },
    });
    throwClock.Advance(TimeSpan.FromSeconds(1));
    var throwResult = await throwScheduler.ProcessDueAsync();
    Assert(throwResult.Count == 1
        && throwResult[0].Outcome == DataVanger.Scheduling.Models.JobRunOutcome.Failed,
        "A runner exception must surface as JobRunOutcome.Failed without crashing the scheduler.");

    // 21l. Snapshot reflects current scheduler state for UI/CLI consumers.
    var snap = throwScheduler.Snapshot();
    Assert(snap.Jobs.Count == 1 && !snap.Paused
        && snap.Jobs[0].LastOutcome == DataVanger.Scheduling.Models.JobRunOutcome.Failed,
        "Scheduler snapshot must expose the latest job status for UI/CLI surfaces.");
}

// ============================================================================
}
