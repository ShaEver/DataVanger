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

// Phase 09 decomposition — Reputation Engine trust-aware scoring & persistence
// (legacy section 15). Faithful verbatim move; private Assert shim -> LegacyAssert.True.
// Filter: ~Reputation.
public class ReputationTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void ReputationEngine_AllLegacyChecks()
    {
        // Reconstructed from legacy section 2: the mega-[Fact] shared this
        // heuristicEvidence list across sections, and section 15 references it
        // (Evidence = heuristicEvidence). Reproduced verbatim so this [Fact] is
        // self-contained — identical values, no behaviour change.
        var heuristicEvidence = new List<Evidence>
        {
            new() { Category = "Heuristic", Description = "Dupla extensão disfarçada", ScoreDelta = 8, Strength = EvidenceStrength.High },
            new() { Category = "Script", Description = "PowerShell EncodedCommand", ScoreDelta = 5, Strength = EvidenceStrength.High },
        };

// 15. Reputation Engine - trust-aware scoring and persistence
// ============================================================================

var repSettings = new AppSettings();
var repDb = new SignatureDatabase();
var repEngine = new ReputationEngine(repDb, repSettings);
var knownGoodEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('1', 64),
    Path = @"C:\Program Files\Vendor\tool.exe",
    Extension = ".exe",
    BaseScore = 10,
    IsKnownSafe = true,
    LastWriteUtc = DateTime.UtcNow.AddDays(-30),
    Evidence = heuristicEvidence,
}, null);
Assert(knownGoodEval.TrustState == ReputationTrustState.KnownGood && knownGoodEval.AdjustedScore < RiskThresholds.Suspect,
    "Known-good reputation must downgrade heuristic-only findings below alert thresholds.");

var knownBadEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('2', 64),
    Path = @"C:\Users\T\Downloads\payload.exe",
    Extension = ".exe",
    BaseScore = 1,
    IsKnownMalicious = true,
    HasConfirmedEvidence = true,
    LastWriteUtc = DateTime.UtcNow,
}, null);
Assert(knownBadEval.TrustState == ReputationTrustState.KnownBad && knownBadEval.Evidence.Any(e => e.CanConfirmMalware),
    "Known-bad reputation must produce confirmed evidence.");

var allowEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('3', 64),
    Path = @"C:\Users\T\AppData\Local\tool.exe",
    Extension = ".exe",
    BaseScore = 8,
    IsUserAllowlisted = true,
    LastWriteUtc = DateTime.UtcNow,
    Evidence = heuristicEvidence,
}, null);
Assert(allowEval.AdjustedScore < RiskThresholds.Suspect && allowEval.UserDecision == ReputationUserDecision.Allowed,
    "User allowlist must downgrade static heuristic findings and record the decision.");

var blockEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('4', 64),
    Path = @"C:\Users\T\Downloads\blocked.exe",
    Extension = ".exe",
    BaseScore = 0,
    IsUserBlocklisted = true,
    LastWriteUtc = DateTime.UtcNow,
}, null);
Assert(blockEval.TrustState == ReputationTrustState.KnownBad && blockEval.Evidence.Any(e => e.CanConfirmMalware),
    "User blocklist must escalate to known-bad reputation with confirmable evidence.");

var signerEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('5', 64),
    Path = @"C:\Program Files\Microsoft\signed.exe",
    Extension = ".exe",
    BaseScore = 9,
    IsSigned = true,
    Publisher = "Microsoft Corporation",
    LastWriteUtc = DateTime.UtcNow.AddDays(-100),
    Evidence = heuristicEvidence,
}, null);
Assert(signerEval.AdjustedScore < 9 && signerEval.SignerStatus == "TrustedSigner",
    "Trusted signer reputation must reduce heuristic score and explain signer trust.");

var firstSeenEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('6', 64),
    Path = @"C:\Users\T\AppData\Local\Temp\new.exe",
    Extension = ".exe",
    BaseScore = 4,
    IsSigned = false,
    LastWriteUtc = DateTime.UtcNow,
}, null);
Assert(firstSeenEval.AdjustedScore > 4 && firstSeenEval.TrustState >= ReputationTrustState.Suspicious,
    "First-seen unsigned executable in a risky path must receive extra scrutiny but not confirmation.");
Assert(!firstSeenEval.Evidence.Any(e => e.CanConfirmMalware),
    "First-seen reputation evidence must never confirm malware by itself.");

var prevalentEntry = new LocalReputationEntry
{
    SHA256 = new string('7', 64),
    SeenCount = 25,
    FirstSeenUtc = DateTime.UtcNow.AddMonths(-2),
    LastSeenUtc = DateTime.UtcNow.AddDays(-1),
};
var prevalenceEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = prevalentEntry.SHA256,
    Path = @"C:\Program Files\Vendor\stable.exe",
    Extension = ".exe",
    BaseScore = 9,
    LastWriteUtc = DateTime.UtcNow.AddMonths(-1),
    Evidence = heuristicEvidence,
}, prevalentEntry);
Assert(prevalenceEval.AdjustedScore < 9 && prevalenceEval.SeenCount == 25,
    "High local prevalence must reduce static-only heuristic risk.");

var browserEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('8', 64),
    Path = @"C:\Users\T\AppData\Local\Google\Chrome\User Data\Default\Extensions\abc\1.0\manifest.json",
    Extension = ".json",
    BaseScore = 9,
    LastWriteUtc = DateTime.UtcNow.AddDays(-10),
    Evidence = new[] { new Evidence { Category = "Browser", Description = "permissoes amplas", ScoreDelta = 4, Strength = EvidenceStrength.Medium } },
}, new LocalReputationEntry { SHA256 = new string('8', 64), SeenCount = 3, FirstSeenUtc = DateTime.UtcNow.AddDays(-20), LastSeenUtc = DateTime.UtcNow.AddDays(-1) });
Assert(browserEval.AdjustedScore < RiskThresholds.High,
    "Legitimate browser extension context with local prevalence must reduce browser-extension false positives.");

var behavioralEval = repEngine.Evaluate(new ReputationSubject
{
    Sha256 = new string('9', 64),
    Path = @"C:\Users\T\Downloads\maybe.exe",
    Extension = ".exe",
    BaseScore = 4,
    LastWriteUtc = DateTime.UtcNow,
}, new LocalReputationEntry { SHA256 = new string('9', 64), SeenCount = 2, BehavioralScore = 8 });
Assert(behavioralEval.AdjustedScore > 4,
    "Suspicious local behavioral history must increase reputation risk without confirming malware.");

string repScratch = Path.Combine(Path.GetTempPath(), "datavanger-reputation-tests.json");
try { File.Delete(repScratch); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
var localRep = new LocalReputationDatabase(repScratch);
string oldHash = new string('A', 64);
string newHash = new string('B', 64);
localRep.ObserveFile(oldHash, @"C:\Users\T\Downloads\same.exe", 12, DateTime.UtcNow.AddDays(-1));
localRep.ObserveFile(newHash, @"C:\Users\T\Downloads\same.exe", 13, DateTime.UtcNow);
localRep.MarkUserDecision(oldHash, ReputationUserDecision.Allowed, "unit test allow");
localRep.Save();
var reloadedRep = new LocalReputationDatabase(repScratch);
Assert(reloadedRep.Get(oldHash)?.UserDecision == ReputationUserDecision.Allowed.ToString(),
    "User trust decisions must persist in the local reputation database.");
Assert(reloadedRep.Get(oldHash) != null && reloadedRep.Get(newHash) != null,
    "Hash changes must create independent reputation records rather than reusing stale trust.");

File.WriteAllText(repScratch, "{ definitely not valid json");
var corruptRep = new LocalReputationDatabase(repScratch);
Assert(corruptRep.Get(oldHash) == null,
    "Corrupted reputation storage must recover as an empty database without throwing.");
try { File.Delete(repScratch); } catch (Exception) { /* temp cleanup - ignore if already removed */ }

var repFinding = new ScanFinding { Score = knownGoodEval.AdjustedScore };
Assert(ThreatClassificationPolicy.Classify(repFinding) == ThreatClass.Clean,
    "Classifier integration must consume reputation-adjusted scores for final verdicts.");
var confirmedDespiteAllow = new ScanFinding { IsBlacklisted = true, Score = RiskThresholds.Critical };
Assert(ThreatClassificationPolicy.Classify(confirmedDespiteAllow) == ThreatClass.ConfirmedMalware,
    "Reputation allow/downgrade logic must not weaken confirmed malicious evidence.");
    }
}
