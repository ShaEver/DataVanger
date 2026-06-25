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

// Phase 09 decomposition — shared test-only support types.
// Promoted verbatim from the file-scoped fixtures at the bottom of
// LegacyParityTests.cs to 'internal' so the per-subsystem test classes
// (sections 25-30 and later migrations) can reference them. Behaviour is
// identical; only the access modifier changed (file -> internal).
// Deterministic in-memory sink for the Behavioral Engine Runtime Binding tests
// (Phase 2 / Step 06). A sink is a passive observer — it records evidence and
// NEVER takes any action.
internal sealed class CollectingBehavioralEvidenceSink
    : DataVanger.Shared.Behavioral.Runtime.IBehavioralRuntimeEvidenceSink
{
    public List<DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeEvidence> Items { get; } = new();

    public void OnEvidence(DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeEvidence evidence)
        => Items.Add(evidence);
}

// Deterministic in-memory sink for the Protected Files Activity Monitor tests
// (Phase 2 / Step 07). A sink is a passive observer — it records evidence and
// NEVER takes any action (no quarantine, no kill, no block, no write-block).
internal sealed class CollectingProtectedFilesEvidenceSink
    : DataVanger.Shared.ProtectedFiles.IProtectedFilesActivityEvidenceSink
{
    public List<DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityEvidence> Items { get; } = new();

    public void OnEvidence(DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityEvidence evidence)
        => Items.Add(evidence);
}

internal class ConfirmingRule : DataVanger.Behavioral.IBehavioralRule
{
    public string RuleId => "T.Confirm";
    public string Title => "Rule that tries to confirm";
    public IReadOnlyList<Evidence> Evaluate(DataVanger.Behavioral.BehavioralEvent ev,
        DataVanger.Behavioral.ProcessAncestry ancestry, DataVanger.Behavioral.BehavioralTimeline timeline)
        => new[] { new Evidence
            {
                Category = "Behavioral",
                Description = "evil",
                ScoreDelta = 50,
                Strength = EvidenceStrength.Confirmed,
                CanConfirmMalware = true,
            }};
}

internal class ThrowingModule : DetectionModuleBase
{
    public override string Name => "Throwing";
    public override DetectionModuleCapabilities Capabilities => DetectionModuleCapabilities.None;
    public override bool Supports(ScanTarget target, ScanContext context) => true;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
        => throw new InvalidOperationException("boom");
}

internal class FixedEvidenceModule : DetectionModuleBase
{
    private readonly Evidence _evidence;
    private readonly DetectionModuleCapabilities _capabilities;
    public FixedEvidenceModule(
        string name,
        Evidence evidence,
        DetectionModuleCapabilities capabilities = DetectionModuleCapabilities.None)
    {
        Name = name;
        _evidence = evidence;
        _capabilities = capabilities;
    }
    public override string Name { get; }
    public override DetectionModuleCapabilities Capabilities => _capabilities;
    public override bool Supports(ScanTarget target, ScanContext context) => true;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
        => new[] { _evidence };
}

internal class TrustStateModule : DetectionModuleBase
{
    private readonly FileTrustState _trustState;
    public TrustStateModule(FileTrustState trustState) { _trustState = trustState; }
    public override string Name => "TrustState";
    public override DetectionModuleCapabilities Capabilities => DetectionModuleCapabilities.None;
    public override bool Supports(ScanTarget target, ScanContext context) => true;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        target.TrustState = _trustState;
        return Array.Empty<Evidence>();
    }
}

internal class FakeScheduledRunner : DataVanger.Scheduling.Abstractions.IScheduledScanRunner
{
    public int Invocations { get; private set; }
    public string? LastRunJobId { get; private set; }
    public DataVanger.Core.ScanProfile LastRunProfile { get; private set; }

    public Task<DataVanger.Scheduling.Abstractions.ScheduledRunResult> RunAsync(
        DataVanger.Scheduling.Models.ScheduledJobDefinition job,
        CancellationToken cancellationToken)
    {
        Invocations++;
        LastRunJobId = job.Id;
        LastRunProfile = job.Profile;
        return Task.FromResult(new DataVanger.Scheduling.Abstractions.ScheduledRunResult
        {
            Outcome = DataVanger.Scheduling.Models.JobRunOutcome.Success,
            FindingsCount = 0,
            Message = "ok",
        });
    }
}

internal class AlwaysFailRunner : DataVanger.Scheduling.Abstractions.IScheduledScanRunner
{
    public int Invocations { get; private set; }
    public Task<DataVanger.Scheduling.Abstractions.ScheduledRunResult> RunAsync(
        DataVanger.Scheduling.Models.ScheduledJobDefinition job,
        CancellationToken cancellationToken)
    {
        Invocations++;
        return Task.FromResult(new DataVanger.Scheduling.Abstractions.ScheduledRunResult
        {
            Outcome = DataVanger.Scheduling.Models.JobRunOutcome.Failed,
            Message = "synthetic failure",
        });
    }
}

internal class ThrowingScheduledRunner : DataVanger.Scheduling.Abstractions.IScheduledScanRunner
{
    public Task<DataVanger.Scheduling.Abstractions.ScheduledRunResult> RunAsync(
        DataVanger.Scheduling.Models.ScheduledJobDefinition job,
        CancellationToken cancellationToken)
        => throw new InvalidOperationException("synthetic scheduler runner failure");
}

internal class ThrowingMemoryRule : DataVanger.Memory.Rules.IMemoryRule
{
    public string RuleId => "Test.ThrowingMemoryRule";
    public string Title => "Test fixture: rule that always throws";
    public bool RequiresBytes => false;
    public IReadOnlyList<DataVanger.Memory.MemoryFinding> Evaluate(
        DataVanger.Memory.ProcessSnapshot process,
        DataVanger.Memory.MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken)
        => throw new InvalidOperationException("synthetic memory rule failure");
}

internal class ThrowingTamperSink : DataVanger.SelfProtection.ITamperEventSink
{
    public bool Publish(DataVanger.SelfProtection.TamperEvent ev)
        => throw new InvalidOperationException("synthetic tamper sink failure");
}

// Deterministic scan recorder for the real-time protection tests. Lives
// outside any local lambda so it can capture a per-request counter and
// optionally delegate to a caller-supplied scan function (defaults to
// a Clean verdict).
internal class ScanRecorder
{
    private readonly Func<DataVanger.Shared.Realtime.RealtimeScanRequest, DataVanger.Shared.Realtime.RealtimeScanResult>? _scan;
    private int _count;
    public ScanRecorder(Func<DataVanger.Shared.Realtime.RealtimeScanRequest, DataVanger.Shared.Realtime.RealtimeScanResult>? scan)
    {
        _scan = scan;
    }
    public int ScanCount => System.Threading.Volatile.Read(ref _count);
    public Task<DataVanger.Shared.Realtime.RealtimeScanResult> ScanAsync(
        DataVanger.Shared.Realtime.RealtimeScanRequest request,
        System.Threading.CancellationToken cancellationToken)
    {
        System.Threading.Interlocked.Increment(ref _count);
        var result = _scan?.Invoke(request) ?? new DataVanger.Shared.Realtime.RealtimeScanResult
        {
            Path = request.Path,
            Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.Clean,
            CompletedAtUtc = request.EnqueuedAtUtc,
        };
        return Task.FromResult(result);
    }
}
