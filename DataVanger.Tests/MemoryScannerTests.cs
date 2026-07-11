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

// Phase 09 decomposition — Memory Scanner: explainable indicators, anti-FP guards, degradation (legacy section 20). Filter: ~Memory.
// Faithful verbatim move; private Assert shim -> LegacyAssert.True preserves
// condition + message. Two-way coupling check passed: no earlier-section method
// locals referenced; engine/bus/bridge/etw are block-scoped using-vars (self-contained).
public class MemoryScannerTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void MemoryScanner_AllLegacyChecks()
    {
// 20. Memory Scanner — explainable indicators, anti-FP guards, degradation
// ============================================================================

// 20a. Protection flag classification
Assert((MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute).IsRwx(),
    "MemoryProtection.IsRwx must be true for R|W|X.");
Assert((MemoryProtection.Read | MemoryProtection.Execute).IsRx(),
    "MemoryProtection.IsRx must be true for R|X (no W).");
Assert(!(MemoryProtection.Read | MemoryProtection.Write).IsExecutable(),
    "MemoryProtection.IsExecutable must be false when X is not set.");
Assert((MemoryProtection.Read | MemoryProtection.Execute).Describe() == "R-X",
    "MemoryProtection.Describe must render the rwx triad.");

// 20b. RwxRegionRule fires only on private RWX, never on image RWX
var rwxPrivate = new MemoryRegion(processId: 1234, baseAddress: 0x10000, size: 4096,
    protection: MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
    kind: MemoryRegionKind.Private);
var rwxImage = new MemoryRegion(processId: 1234, baseAddress: 0x20000, size: 4096,
    protection: MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
    kind: MemoryRegionKind.Image, backingPath: @"C:\Windows\System32\foo.dll");
var rwxRule = new RwxRegionRule();
var rwxProc = new ProcessSnapshot(1234, "victim.exe", isAccessible: true);
var rwxFindings = rwxRule.Evaluate(rwxProc, rwxPrivate, Array.Empty<byte>(), CancellationToken.None);
Assert(rwxFindings.Count == 1 && rwxFindings[0].Kind == MemoryFindingKind.RwxPrivateRegion
    && rwxFindings[0].Severity == MemoryScanSeverity.Medium,
    "RwxRegionRule must fire on private RWX with Medium severity.");
Assert(!rwxFindings[0].CanConfirmMalware,
    "RwxRegionRule findings must never confirm malware.");
Assert(rwxRule.Evaluate(rwxProc, rwxImage, Array.Empty<byte>(), CancellationToken.None).Count == 0,
    "RwxRegionRule must NOT fire on MEM_IMAGE regions (loaded DLLs may be RWX during patching).");

// 20c. AnonymousExecutableRule fires on RX private without backing path
var anonRxPrivate = new MemoryRegion(1234, 0x30000, 8192,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Private);
var imageRxBacked = new MemoryRegion(1234, 0x40000, 8192,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Image, backingPath: @"C:\Windows\System32\kernel32.dll");
var anonRule = new AnonymousExecutableRule();
var anonFindings = anonRule.Evaluate(rwxProc, anonRxPrivate, Array.Empty<byte>(), CancellationToken.None);
Assert(anonFindings.Count == 1 && anonFindings[0].Kind == MemoryFindingKind.AnonymousExecutableRegion,
    "AnonymousExecutableRule must flag RX private memory without backing image.");
Assert(anonRule.Evaluate(rwxProc, imageRxBacked, Array.Empty<byte>(), CancellationToken.None).Count == 0,
    "AnonymousExecutableRule must NOT flag image-backed RX regions.");

// 20d. ReflectivePeIndicatorRule detects MZ/PE inside private executable memory
byte[] pePayload = new byte[256];
pePayload[0] = (byte)'M'; pePayload[1] = (byte)'Z';
BitConverter.GetBytes(0x80).CopyTo(pePayload, 0x3C);
pePayload[0x80] = (byte)'P'; pePayload[0x81] = (byte)'E';
pePayload[0x82] = 0; pePayload[0x83] = 0;
var refRegion = new MemoryRegion(7777, 0x50000, 4096,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Private);
var refRule = new ReflectivePeIndicatorRule();
var refFindings = refRule.Evaluate(new ProcessSnapshot(7777, "victim.exe"), refRegion, pePayload,
    CancellationToken.None);
Assert(refFindings.Count == 1 && refFindings[0].Kind == MemoryFindingKind.ReflectivePeIndicator
    && refFindings[0].Severity == MemoryScanSeverity.High,
    "ReflectivePeIndicatorRule must detect MZ+PE in private executable memory at High severity.");
Assert(!refFindings[0].CanConfirmMalware,
    "ReflectivePeIndicatorRule must NEVER confirm malware on its own.");

// PE magic in image-backed region must NOT fire (it's just a normally loaded DLL).
var imageRefRegion = new MemoryRegion(7777, 0x60000, 4096,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Image, backingPath: @"C:\Windows\System32\foo.dll");
Assert(refRule.Evaluate(new ProcessSnapshot(7777, "victim.exe"), imageRefRegion, pePayload,
        CancellationToken.None).Count == 0,
    "ReflectivePeIndicatorRule must not fire on image-backed regions.");

// 20e. ShellcodeLikePatternRule: NOP sled and decoder-stub prologue
byte[] nopSledBytes = new byte[128];
for (int i = 0; i < 64; i++) nopSledBytes[i] = 0x90; // long NOP sled
nopSledBytes[64] = 0x48; nopSledBytes[65] = 0x31; // some payload after sled
var nopRegion = new MemoryRegion(8888, 0x70000, 4096,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Private);
var shellRule = new ShellcodeLikePatternRule();
var shellFindings = shellRule.Evaluate(new ProcessSnapshot(8888, "victim.exe"),
    nopRegion, nopSledBytes, CancellationToken.None);
Assert(shellFindings.Count == 1
    && shellFindings[0].Kind == MemoryFindingKind.ShellcodeLikePattern
    && shellFindings[0].Severity == MemoryScanSeverity.Medium,
    "ShellcodeLikePatternRule must detect a long NOP sled in private executable memory.");
Assert(!shellFindings[0].CanConfirmMalware,
    "Shellcode-pattern findings must never confirm malware.");

byte[] stubBytes = new byte[64];
stubBytes[0] = 0xFC; stubBytes[1] = 0x48; stubBytes[2] = 0x83; stubBytes[3] = 0xE4; stubBytes[4] = 0xF0;
Assert(shellRule.Evaluate(new ProcessSnapshot(8888, "victim.exe"),
        new MemoryRegion(8888, 0x71000, 4096,
            MemoryProtection.Read | MemoryProtection.Execute, MemoryRegionKind.Private),
        stubBytes, CancellationToken.None).Count == 1,
    "ShellcodeLikePatternRule must detect classic x64 'cld; and rsp,-16' decoder prologue.");

// Random-looking but non-malicious bytes (no NOP sled, no decoder stub) must not fire.
byte[] benignExec = new byte[256];
for (int i = 0; i < benignExec.Length; i++) benignExec[i] = (byte)(i & 0x7F);
Assert(shellRule.Evaluate(new ProcessSnapshot(8888, "victim.exe"),
        new MemoryRegion(8888, 0x72000, 4096,
            MemoryProtection.Read | MemoryProtection.Execute, MemoryRegionKind.Private),
        benignExec, CancellationToken.None).Count == 0,
    "ShellcodeLikePatternRule must NOT fire on benign-looking executable bytes.");

// 20f. HighEntropyExecutableRule on packed-ish payload
byte[] packedBytes = new byte[1024];
var entropyRng = new Random(0xC0FFEE);
entropyRng.NextBytes(packedBytes);
var packedRegion = new MemoryRegion(9999, 0x80000, packedBytes.Length,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Private);
var entropyRule = new HighEntropyExecutableRule(threshold: 7.0);
var entropyFindings = entropyRule.Evaluate(new ProcessSnapshot(9999, "victim.exe"),
    packedRegion, packedBytes, CancellationToken.None);
Assert(entropyFindings.Count == 1 && entropyFindings[0].Severity == MemoryScanSeverity.Low,
    "HighEntropyExecutableRule must flag random-like executable bytes at Low severity.");

// Low-entropy uniform bytes must not fire.
byte[] uniform = new byte[1024];
Array.Fill(uniform, (byte)0x41);
Assert(entropyRule.Evaluate(new ProcessSnapshot(9999, "victim.exe"),
        new MemoryRegion(9999, 0x81000, 1024,
            MemoryProtection.Read | MemoryProtection.Execute, MemoryRegionKind.Private),
        uniform, CancellationToken.None).Count == 0,
    "HighEntropyExecutableRule must NOT flag uniformly-filled executable memory.");

// 20g. SuspiciousModulePathRule: Temp-path module on an unsigned process
var tempImage = new MemoryRegion(1111, 0x90000, 8192,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Image,
    backingPath: @"C:\Users\T\AppData\Local\Temp\sideload.dll");
var unsignedProc = new ProcessSnapshot(1111, "victim.exe", isSigned: false);
var signedProc = new ProcessSnapshot(2222, "trusted.exe", isSigned: true);
var modPathRule = new SuspiciousModulePathRule();
Assert(modPathRule.Evaluate(unsignedProc, tempImage, Array.Empty<byte>(), CancellationToken.None).Count == 1,
    "SuspiciousModulePathRule must flag Temp-loaded modules on unsigned processes.");
Assert(modPathRule.Evaluate(signedProc, tempImage, Array.Empty<byte>(), CancellationToken.None).Count == 0,
    "SuspiciousModulePathRule must respect trusted signer status (no fire on signed process).");

// 20h. HollowingIndicatorRule: image-sized private executable region at aligned base
var hollowProc = new ProcessSnapshot(3333, "hollow.exe", imagePath: @"C:\Windows\System32\hollow.exe");
var hollowRegion = new MemoryRegion(3333, 0x140000000UL, 64 * 1024,
    protection: MemoryProtection.Read | MemoryProtection.Execute,
    kind: MemoryRegionKind.Private);
var hollowRule = new HollowingIndicatorRule();
var hollowFindings = hollowRule.Evaluate(hollowProc, hollowRegion, Array.Empty<byte>(), CancellationToken.None);
Assert(hollowFindings.Count == 1 && hollowFindings[0].Severity == MemoryScanSeverity.High,
    "HollowingIndicatorRule must escalate aligned image-sized private executable regions to High.");
Assert(!hollowFindings[0].CanConfirmMalware,
    "Hollowing heuristic must NEVER confirm malware on its own.");

// 20i. MemoryEvidenceFactory enforces the anti-FP contract
var factoryEvidence = MemoryEvidenceFactory.FromFinding(hollowFindings[0]);
Assert(factoryEvidence.Category == "Memory"
    && factoryEvidence.Strength == EvidenceStrength.High
    && !factoryEvidence.CanConfirmMalware,
    "MemoryEvidenceFactory must map High severity to High strength and never confirm.");
var bogusConfirmAttempt = new MemoryFinding(
    MemoryFindingKind.RwxPrivateRegion, 1, "x.exe", 0x1000, 4096,
    MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
    MemoryRegionKind.Private, MemoryScanSeverity.High,
    "synthetic", scoreDelta: 9999);
var clampedEvidence = MemoryEvidenceFactory.FromFinding(bogusConfirmAttempt);
Assert(clampedEvidence.ScoreDelta <= 6 && !clampedEvidence.CanConfirmMalware,
    "MemoryEvidenceFactory must clamp inflated ScoreDelta and refuse confirmation.");

// 20j. End-to-end: MemoryScannerEngine + InMemoryMemoryReader
var reader = new InMemoryMemoryReader();
reader.AddProcess(new ProcessSnapshot(4242, "victim.exe", imagePath: @"C:\Users\T\Downloads\victim.exe"));
reader.AddRegion(new MemoryRegion(4242, 0x100000, 4096,
    MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
    MemoryRegionKind.Private));
reader.AddRegion(new MemoryRegion(4242, 0x110000, 4096,
    MemoryProtection.Read | MemoryProtection.Execute,
    MemoryRegionKind.Private), backingBytes: pePayload);
reader.AddRegion(new MemoryRegion(4242, 0x120000, 8192,
    MemoryProtection.Read | MemoryProtection.Execute,
    MemoryRegionKind.Image,
    backingPath: @"C:\Users\T\AppData\Local\Temp\drop.dll"));
var memScanner = new MemoryScannerEngine(reader);
var memResult = memScanner.Scan(new MemoryScannerOptions(), CancellationToken.None);
Assert(!memResult.IsDegraded,
    "End-to-end memory scan with the in-memory reader must complete without degradation.");
Assert(memResult.Findings.Count >= 3,
    "Memory scan must surface RWX + reflective-PE + suspicious-module findings together.");
Assert(memResult.Findings.Any(f => f.Kind == MemoryFindingKind.RwxPrivateRegion)
    && memResult.Findings.Any(f => f.Kind == MemoryFindingKind.ReflectivePeIndicator)
    && memResult.Findings.Any(f => f.Kind == MemoryFindingKind.SuspiciousModulePath),
    "Memory scan must include each of the three seeded indicators.");
Assert(memResult.Findings.All(f => !f.CanConfirmMalware),
    "No memory finding may ever be ConfirmedMalware.");

// 20k. Apply to a ScanFinding — Memory evidence alone must NEVER trip ConfirmedMalware,
// and AntiFalsePositivePolicy must clamp the score to the HighRisk band.
var memFinding = new ScanFinding
{
    Path = @"C:\Users\T\Downloads\victim.exe",
    Score = RiskThresholds.Suspect,
    Evidence = new List<Evidence>(),
};
var memCorr = new MemoryCorrelationEngine();
int memAdded = memCorr.Apply(memFinding, processId: 4242, memResult.Findings);
Assert(memAdded > 0,
    "MemoryCorrelationEngine.Apply must add evidence/score for matching PID findings.");
Assert(memFinding.Evidence.All(e => !e.CanConfirmMalware),
    "Memory evidence pushed into a ScanFinding must never be ConfirmedMalware.");
Assert(ThreatClassificationPolicy.Classify(memFinding) != ThreatClass.ConfirmedMalware,
    "Memory-only evidence must NEVER cause ThreatClassificationPolicy to confirm malware.");
Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(memFinding),
    "Memory-only evidence must NEVER authorize automatic quarantine.");
Assert(memFinding.Score <= RiskThresholds.High,
    "Memory-only evidence must be clamped to the HighRisk band by AntiFalsePositivePolicy.");

// 20l. Correlation: Memory finding + Behavioral InjectionIndicator on same PID upgrades evidence
var injectionEvent = new DataVanger.Behavioral.BehavioralEvent(
    DataVanger.Behavioral.BehavioralEventKind.InjectionIndicator,
    pid: 4242, parentPid: 0, processName: "victim.exe",
    imagePath: @"C:\Users\T\Downloads\victim.exe", commandLine: "",
    targetPath: "", extraTag: "etw-inject",
    severity: DataVanger.Behavioral.BehavioralSeverity.High,
    description: "ETW injection event",
    timestampUtc: DateTime.UtcNow);
var correlated = memCorr.CorrelateForProcess(4242, memResult.Findings,
    new[] { injectionEvent });
Assert(correlated.Any(e => e.Description.Contains("correlação", StringComparison.OrdinalIgnoreCase)),
    "MemoryCorrelationEngine must annotate findings when an injection event for the same PID exists.");
Assert(correlated.All(e => !e.CanConfirmMalware),
    "Memory + injection correlation must still NEVER confirm malware.");

// 20m. Graceful degradation: NullMemoryReader returns PlatformUnsupported, never throws
var nullScanner = MemoryScannerFactory.CreateSafeDefault();
Assert(!nullScanner.IsSupported,
    "Default safe scanner must report IsSupported=false on environments without a real reader.");
var nullResult = nullScanner.Scan(new MemoryScannerOptions(), CancellationToken.None);
Assert(nullResult.IsDegraded && nullResult.Degradation == MemoryScanDegradationReason.PlatformUnsupported,
    "Default safe scanner must degrade to PlatformUnsupported instead of throwing.");
Assert(nullResult.Findings.Count == 0,
    "Default safe scanner must produce zero findings on unsupported hosts.");

// 20n. Disabled by configuration
var disabledScanner = new MemoryScannerEngine(reader);
var disabledResult = disabledScanner.Scan(new MemoryScannerOptions { Enabled = false }, CancellationToken.None);
Assert(disabledResult.Degradation == MemoryScanDegradationReason.DisabledByConfiguration,
    "MemoryScannerEngine must return DisabledByConfiguration when options.Enabled is false.");

// 20o. Process exits between enumeration and region walk — no crash, just empty regions
var raceReader = new InMemoryMemoryReader();
raceReader.AddProcess(new ProcessSnapshot(5555, "vanishing.exe", isAccessible: true));
raceReader.AddRegion(new MemoryRegion(5555, 0x10000, 4096,
    MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
    MemoryRegionKind.Private));
raceReader.RemoveProcess(5555); // process disappears
var raceScanner = new MemoryScannerEngine(raceReader);
var raceResult = raceScanner.Scan(new MemoryScannerOptions(), CancellationToken.None);
Assert(raceResult.Findings.Count == 0,
    "Disappearing processes must yield zero findings, not crashes.");
Assert(raceResult.Degradation == MemoryScanDegradationReason.None,
    "A vanished process is normal — no degradation flag should be raised.");

// 20p. Access-denied process: no findings, no exception, counted as inaccessible
var deniedReader = new InMemoryMemoryReader();
deniedReader.AddProcess(new ProcessSnapshot(6060, "protected.exe", isAccessible: false));
deniedReader.AddRegion(new MemoryRegion(6060, 0x20000, 4096,
    MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
    MemoryRegionKind.Private));
var deniedScanner = new MemoryScannerEngine(deniedReader);
var deniedResult = deniedScanner.Scan(new MemoryScannerOptions(), CancellationToken.None);
Assert(deniedResult.ProcessesInaccessible == 1 && deniedResult.Findings.Count == 0,
    "Access-denied processes must be counted as inaccessible and produce zero findings.");

// 20q. Cancellation: an already-cancelled token degrades to Cancelled
using var cancelledCts = new CancellationTokenSource();
cancelledCts.Cancel();
var cancelResult = new MemoryScannerEngine(reader).Scan(new MemoryScannerOptions(), cancelledCts.Token);
Assert(cancelResult.Degradation == MemoryScanDegradationReason.Cancelled,
    "MemoryScannerEngine must surface Cancelled when the caller cancels before completion.");

// 20r. Hard limits: MaxFindings caps the result list
var heavyReader = new InMemoryMemoryReader();
heavyReader.AddProcess(new ProcessSnapshot(7000, "noisy.exe"));
for (int i = 0; i < 50; i++)
{
    heavyReader.AddRegion(new MemoryRegion(7000, (ulong)(0x10000 + i * 0x1000), 4096,
        MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
        MemoryRegionKind.Private));
}
var limitedResult = new MemoryScannerEngine(heavyReader).Scan(
    new MemoryScannerOptions { MaxFindings = 5 }, CancellationToken.None);
Assert(limitedResult.Findings.Count <= 5
    && limitedResult.Degradation == MemoryScanDegradationReason.LimitsExceeded,
    "MaxFindings must hard-cap the result list and mark the result as LimitsExceeded.");

// 20s. Behavioral bridge: memory findings are published as InjectionIndicator events,
// but the behavioral pipeline still clamps them — never ConfirmedMalware.
using (var bridgeBus = new DataVanger.Behavioral.BehavioralEventBus(capacity: 64))
{
    var received = new System.Collections.Concurrent.ConcurrentBag<DataVanger.Behavioral.BehavioralEvent>();
    using var sub = bridgeBus.Subscribe(e => received.Add(e));
    var bridge = new MemoryBehavioralBridge(bridgeBus);
    bridge.Publish(memResult.Findings);
    bridgeBus.DrainNow();
    Assert(bridge.PublishedCount == memResult.Findings.Count,
        "MemoryBehavioralBridge must publish one BehavioralEvent per memory finding.");
    Assert(received.All(e => e.Kind == DataVanger.Behavioral.BehavioralEventKind.InjectionIndicator),
        "Bridge must map memory findings onto the InjectionIndicator behavioral kind.");
    Assert(received.All(e => e.Severity <= DataVanger.Behavioral.BehavioralSeverity.High),
        "Bridge must never publish a behavioral event above High severity from memory findings.");
}

// 20t. Region analyzer isolates rule exceptions — one bad rule must not stop the scan.
var throwingReader = new InMemoryMemoryReader();
throwingReader.AddProcess(new ProcessSnapshot(8080, "test.exe"));
throwingReader.AddRegion(new MemoryRegion(8080, 0x10000, 4096,
    MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
    MemoryRegionKind.Private));
var throwingAnalyzer = new MemoryRegionAnalyzer(new IMemoryRule[]
{
    new ThrowingMemoryRule(),
    new RwxRegionRule(),
});
var throwingFindings = throwingAnalyzer.Analyze(
    new ProcessSnapshot(8080, "test.exe"),
    new MemoryRegion(8080, 0x10000, 4096,
        MemoryProtection.Read | MemoryProtection.Write | MemoryProtection.Execute,
        MemoryRegionKind.Private),
    throwingReader, 1024, CancellationToken.None);
Assert(throwingFindings.Count == 1 && throwingFindings[0].Kind == MemoryFindingKind.RwxPrivateRegion,
    "MemoryRegionAnalyzer must isolate a throwing rule so other rules still run.");
    }
}
