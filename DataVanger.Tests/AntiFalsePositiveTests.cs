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

// Focused, self-contained anti-false-positive contract tests so the suite can be
// run via:  dotnet test --filter "FullyQualifiedName~AntiFalsePositive".
// These assertions are verbatim copies of sections 1, 2 and 7 of the legacy runner
// (which remain present, unchanged, inside LegacyParityTests for full parity).
public class AntiFalsePositiveTests
{
    private static void Assert(bool condition, string message) => Xunit.Assert.True(condition, message);

    [Xunit.Fact]
    public void Classify_LegacyStaticPolicy_HonoursConfirmationContract()
    {
var heuristicOnly = new ScanFinding
{
    Path = @"C:\Users\Test\AppData\Roaming\svchost.exe",
    Score = RiskThresholds.Critical + 20,
    Reasons = "Nome de processo de sistema fora de System32; execução dinâmica; persistência"
};
Assert(ThreatClassificationPolicy.Classify(heuristicOnly) == ThreatClass.HighRisk,
    "Heuristics alone must not classify as confirmed malware.");
Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(heuristicOnly),
    "Heuristics alone must not allow automatic action.");

var blacklisted = new ScanFinding
{
    Path = @"C:\Users\Test\Downloads\payload.exe",
    Score = RiskThresholds.Critical,
    IsBlacklisted = true
};
Assert(ThreatClassificationPolicy.Classify(blacklisted) == ThreatClass.ConfirmedMalware,
    "Blacklist hash must classify as confirmed malware.");
Assert(ThreatClassificationPolicy.AllowsAutomaticAction(blacklisted),
    "Confirmed malware may allow automatic action.");

var confirmedRule = new ScanFinding
{
    Path = @"C:\Users\Test\Downloads\payload.exe",
    Score = RiskThresholds.Critical,
    HasConfirmedSignature = true
};
Assert(ThreatClassificationPolicy.Classify(confirmedRule) == ThreatClass.ConfirmedMalware,
    "Confirmed signature must classify as confirmed malware.");

var nonConfirmedRule = new ScanFinding
{
    Path = @"C:\Users\Test\Downloads\suspicious.ps1",
    Score = RiskThresholds.High,
    HasConfirmedSignature = false
};
Assert(ThreatClassificationPolicy.Classify(nonConfirmedRule) == ThreatClass.HighRisk,
    "Non-confirmed signatures or heuristics should remain high risk.");

var clean = new ScanFinding
{
    Path = @"C:\Windows\System32\notepad.exe",
    Score = 0,
    IsSigned = true,
    Publisher = "Microsoft Windows"
};
Assert(ThreatClassificationPolicy.Classify(clean) == ThreatClass.Clean,
    "Signed clean item with no score should remain clean.");
    }

    [Xunit.Fact]
    public void Policy_DistinguishesConfirmedFromHeuristic_AndClamps()
    {
var heuristicEvidence = new List<Evidence>
{
    new() { Category = "Heuristic", Description = "Dupla extensão disfarçada", ScoreDelta = 8, Strength = EvidenceStrength.High },
    new() { Category = "Script", Description = "PowerShell EncodedCommand", ScoreDelta = 5, Strength = EvidenceStrength.High },
};
Assert(!AntiFalsePositivePolicy.HasConfirmedEvidence(heuristicEvidence),
    "Heuristic-only evidence must not be reported as confirmed.");

var confirmedEvidence = new List<Evidence>
{
    new() { Category = "Reputation", Description = "Hash bate com base de malware", ScoreDelta = 100,
            Strength = EvidenceStrength.Confirmed, CanConfirmMalware = true },
};
Assert(AntiFalsePositivePolicy.HasConfirmedEvidence(confirmedEvidence),
    "Confirmed evidence must be recognised.");

int clamped = AntiFalsePositivePolicy.ClampToHighRiskWhenUnconfirmed(
    score: RiskThresholds.Critical + 50,
    finding: new ScanFinding(),
    evidence: heuristicEvidence);
Assert(clamped == RiskThresholds.High,
    "Critical score with heuristic-only evidence must be clamped to High.");
    }

    [Xunit.Fact]
    public void Clamp_ConfirmedFindings_AreNotClamped()
    {
var confirmedEvidence = new List<Evidence>
{
    new() { Category = "Reputation", Description = "Hash bate com base de malware", ScoreDelta = 100,
            Strength = EvidenceStrength.Confirmed, CanConfirmMalware = true },
};
var confirmedFinding = new ScanFinding { IsBlacklisted = true, Score = 100 };
int notClamped = AntiFalsePositivePolicy.ClampToHighRiskWhenUnconfirmed(100, confirmedFinding, confirmedEvidence);
Assert(notClamped == 100,
    "Confirmed findings must NOT be clamped — they keep their full score.");
    }
}
