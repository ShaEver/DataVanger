using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Memory;
using DataVanger.Runtime;
using DataVanger.Service.Runtime;
using DataVanger.Shared.Behavioral.Runtime;
using DataVanger.Shared.RuntimeEvents;
using DataVanger.Shared.Service;
using Xunit;

namespace DataVanger.Tests;

public sealed class ResidentRuntimeWiringTests
{
    [Fact]
    public async Task MemoryStartupPass_RunsOnce_PublishesBehavioralEvidence_AndNeverConfirms()
    {
        var finding = CreateMemoryFinding();
        var scanner = new FixedMemoryScanner(new MemoryScanResult(
            new[] { finding },
            processesEnumerated: 1,
            processesScanned: 1,
            processesInaccessible: 0,
            regionsExamined: 1,
            bytesExamined: 4096,
            degradation: MemoryScanDegradationReason.None));

        using var runtime = new DataVangerServiceRuntime(
            new DataVangerServiceConfiguration { EnableMemoryScanPass = true },
            DataVangerRuntimeMode.Service,
            memoryScanner: scanner);

        await runtime.StartAsync(CancellationToken.None);
        await runtime.StartAsync(CancellationToken.None);

        Assert.Equal(1, scanner.ScanCount);
        var status = runtime.GetStatusSnapshot();
        var memory = Assert.Single(status.Modules, m => m.Name == "MemoryRuntime");
        Assert.Equal(RuntimeModuleAvailability.Passive, memory.Availability);
        Assert.False(memory.IsActiveProtection);
        Assert.False(status.HasActiveProtection);

        var evidence = runtime.GetRecentRuntimeEvidence();
        Assert.Contains(evidence, item => item.RuleId == "BRB-R6");
        Assert.All(evidence, item => Assert.False(item.IsConfirmedMalware));
        Assert.All(evidence, item => Assert.True(item.Severity <= BehavioralRuntimeSeverity.HighRisk));
    }

    [Fact]
    public async Task MemoryStartupPass_UnsupportedReader_DegradesWithoutFailingService()
    {
        using var runtime = new DataVangerServiceRuntime(
            new DataVangerServiceConfiguration { EnableMemoryScanPass = true },
            DataVangerRuntimeMode.Service);

        await runtime.StartAsync(CancellationToken.None);

        Assert.Equal(DataVangerServiceState.Running, runtime.State);
        var status = runtime.GetStatusSnapshot();
        var memory = Assert.Single(status.Modules, m => m.Name == "MemoryRuntime");
        Assert.Equal(RuntimeModuleAvailability.Degraded, memory.Availability);
        Assert.False(status.HasActiveProtection);
        Assert.Contains(status.Warnings, warning =>
            warning.Contains("Memory runtime pass degraded", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AmsiSubmission_FlowsThroughScriptObserved_ToBehavioralEvidence()
    {
        using var runtime = new DataVangerServiceRuntime(
            DataVangerServiceConfiguration.SafeDefaults(),
            DataVangerRuntimeMode.Service);
        await runtime.StartAsync(CancellationToken.None);

        var published = runtime.SubmitAmsiContent(
            "powershell.exe",
            "powershell.exe -EncodedCommand QQBCAA== -WindowStyle Hidden",
            4242);

        Assert.True(published > 0);
        var evidence = runtime.GetRecentRuntimeEvidence();
        Assert.Contains(evidence, item => item.RuleId == "BRB-R2");
        Assert.All(evidence, item => Assert.False(item.IsConfirmedMalware));
        Assert.All(evidence, item => Assert.True(item.Severity <= BehavioralRuntimeSeverity.HighRisk));

        var status = runtime.GetStatusSnapshot();
        var amsi = Assert.Single(status.Modules, m => m.Name == "AmsiRuntime");
        Assert.Equal(RuntimeModuleAvailability.Passive, amsi.Availability);
        Assert.False(amsi.IsActiveProtection);
        Assert.False(status.HasActiveProtection);
    }

    [Fact]
    public async Task AmsiSubmission_BenignContent_ProducesNoEvidenceOrAction()
    {
        using var runtime = new DataVangerServiceRuntime(
            DataVangerServiceConfiguration.SafeDefaults(),
            DataVangerRuntimeMode.Service);
        await runtime.StartAsync(CancellationToken.None);

        var before = runtime.GetRecentRuntimeEvidence().Count;
        var published = runtime.SubmitAmsiContent(
            "powershell.exe",
            "powershell.exe -NoProfile -File build.ps1",
            4243);

        Assert.Equal(0, published);
        Assert.Equal(before, runtime.GetRecentRuntimeEvidence().Count);
        Assert.False(runtime.GetStatusSnapshot().HasActiveProtection);
    }

    [Fact]
    public void Bridges_EmitOnlyHeuristicRuntimeCategoriesAndIndicatorMetadata()
    {
        var memoryEvent = MemoryRuntimeBridge.Map(CreateMemoryFinding());
        Assert.Equal(RuntimeEventSource.MemoryScanner, memoryEvent.Source);
        Assert.Equal(RuntimeEventCategory.InjectionObserved, memoryEvent.Category);
        Assert.Contains(memoryEvent.Metadata.Keys, key =>
            key.StartsWith("etw.indicator.", StringComparison.Ordinal));

        var amsiEvent = AmsiRuntimeBridge.Map(new RuntimeTelemetryEvent(
            RuntimeTelemetryEventKind.AmsiScan,
            "memory-amsi",
            pid: 99,
            parentPid: 0,
            processName: "powershell.exe",
            imagePath: string.Empty,
            commandLine: string.Empty,
            scriptContent: "powershell.exe -EncodedCommand QQ==",
            extraTag: "encoded",
            timestampUtc: DateTime.UtcNow));
        Assert.Equal(RuntimeEventSource.AmsiContentAnalysis, amsiEvent.Source);
        Assert.Equal(RuntimeEventCategory.ScriptObserved, amsiEvent.Category);
        Assert.True(amsiEvent.Metadata.ContainsKey("etw.indicator.encoded"));
        Assert.True(amsiEvent.Metadata.ContainsKey("etw.indicator.powershell-encoded-command"));
        Assert.False(amsiEvent.Metadata.ContainsKey("etw.command_line"));
    }

    private static MemoryFinding CreateMemoryFinding() => new(
        MemoryFindingKind.RwxPrivateRegion,
        processId: 31337,
        processName: "sample.exe",
        regionBase: 0x1000,
        regionSize: 4096,
        protection: MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
        regionKind: MemoryRegionKind.Private,
        severity: MemoryScanSeverity.High,
        description: "Synthetic RWX private region for resident bridge validation.",
        scoreDelta: 6,
        timestampUtc: DateTime.UtcNow);

    private sealed class FixedMemoryScanner : IMemoryScanner
    {
        private readonly MemoryScanResult _result;
        private int _scanCount;

        public FixedMemoryScanner(MemoryScanResult result) => _result = result;

        public bool IsSupported => true;
        public int ScanCount => Volatile.Read(ref _scanCount);

        public MemoryScanResult Scan(MemoryScannerOptions options, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref _scanCount);
            return _result;
        }
    }
}
