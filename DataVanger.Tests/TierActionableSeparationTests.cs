using System.Collections.Generic;
using DataVanger.Classification;
using DataVanger.Core;

// BETA 11E — actionable-corroboration tier gate + evidence category model.
// A trusted/system file cannot reach HighRisk on summed technical/informational
// evidence alone; it needs an actionable corroborating signal. Numeric thresholds,
// the Critical clamp, and ConfirmedMalware behavior are unchanged, and unsigned/
// user-writable files are not protected by the gate.
// Filters: ~AntiFalsePositive, ~Detection, ~Classification, ~Scan.
public class TierActionableSeparationTests
{
    private static Evidence Ev(string cat, string desc, int delta, EvidenceStrength s, bool confirm = false) =>
        new() { Category = cat, Description = desc, ScoreDelta = delta, Strength = s, CanConfirmMalware = confirm };

    // ── HighRisk actionable-corroboration gate ──

    [Xunit.Fact]
    public void TrustedSystem_TechnicalOnly_GatedToSuspect()
    {
        var f = new ScanFinding { Score = 12, TrustedOrSystemContext = true, HasActionableCorroboration = false };
        Xunit.Assert.Equal(ThreatClass.Suspect, ThreatClassificationPolicy.Classify(f));
        Xunit.Assert.False(ThreatClassificationPolicy.AllowsAutomaticAction(f));
        Xunit.Assert.Equal("Investigar/monitorar", ThreatClassificationPolicy.RecommendedAction(f));
    }

    [Xunit.Fact]
    public void TrustedSystem_WithActionable_StaysHighRisk()
    {
        var f = new ScanFinding { Score = 12, TrustedOrSystemContext = true, HasActionableCorroboration = true };
        Xunit.Assert.Equal(ThreatClass.HighRisk, ThreatClassificationPolicy.Classify(f));
    }

    [Xunit.Fact]
    public void Untrusted_NotGated_StaysHighRisk()
    {
        // Unsigned/user-writable/masquerading files (TrustedOrSystemContext = false) are not protected.
        var f = new ScanFinding { Score = 12, TrustedOrSystemContext = false, HasActionableCorroboration = false };
        Xunit.Assert.Equal(ThreatClass.HighRisk, ThreatClassificationPolicy.Classify(f));
    }

    [Xunit.Fact]
    public void KnownMaliciousHash_BypassesGate_ConfirmedMalware()
    {
        var f = new ScanFinding { Score = 12, IsBlacklisted = true, TrustedOrSystemContext = true, HasActionableCorroboration = false };
        Xunit.Assert.Equal(ThreatClass.ConfirmedMalware, ThreatClassificationPolicy.Classify(f));
        Xunit.Assert.True(ThreatClassificationPolicy.AllowsAutomaticAction(f));
    }

    [Xunit.Fact]
    public void ConfirmedYara_BypassesGate_ConfirmedMalware()
    {
        var f = new ScanFinding { Score = 12, HasConfirmedSignature = true, TrustedOrSystemContext = true, HasActionableCorroboration = false };
        Xunit.Assert.Equal(ThreatClass.ConfirmedMalware, ThreatClassificationPolicy.Classify(f));
    }

    [Xunit.Fact]
    public void Gate_DoesNotAffect_SuspectOrCleanScores()
    {
        Xunit.Assert.Equal(ThreatClass.Suspect, ThreatClassificationPolicy.Classify(
            new ScanFinding { Score = 7, TrustedOrSystemContext = true, HasActionableCorroboration = false }));
        Xunit.Assert.Equal(ThreatClass.Clean, ThreatClassificationPolicy.Classify(
            new ScanFinding { Score = 3, TrustedOrSystemContext = true }));
    }

    [Xunit.Fact]
    public void DefaultFinding_NumericTiersUnchanged()
    {
        // No context set (default false) -> legacy purely-numeric classification preserved.
        Xunit.Assert.Equal(ThreatClass.HighRisk, ThreatClassificationPolicy.Classify(new ScanFinding { Score = 9 }));
        Xunit.Assert.Equal(ThreatClass.Suspect, ThreatClassificationPolicy.Classify(new ScanFinding { Score = 6 }));
        Xunit.Assert.Equal(ThreatClass.Clean, ThreatClassificationPolicy.Classify(new ScanFinding { Score = 5 }));
    }

    // ── Evidence category model ──

    [Xunit.Fact]
    public void EvidenceModel_ClassifiesCategories()
    {
        Xunit.Assert.Equal(EvidenceClass.Confirmed,
            EvidenceClassification.Classify(Ev("Signature", "confirmed YARA", 50, EvidenceStrength.Confirmed, confirm: true)));
        Xunit.Assert.Equal(EvidenceClass.Actionable,
            EvidenceClassification.Classify(Ev("PE", "Seção executável e gravável (RWX): .x", 4, EvidenceStrength.High)));
        Xunit.Assert.Equal(EvidenceClass.Actionable,
            EvidenceClassification.Classify(Ev("PE", "Correlação PE forte: indicadores", 4, EvidenceStrength.High)));
        Xunit.Assert.Equal(EvidenceClass.Technical,
            EvidenceClassification.Classify(Ev("PE", "Imports de injeção/process memory combinados: VirtualAlloc, OpenProcess", 4, EvidenceStrength.High)));
        Xunit.Assert.Equal(EvidenceClass.Informational,
            EvidenceClassification.Classify(Ev("Reputation", "Prevalência local estável", -4, EvidenceStrength.Info)));
        Xunit.Assert.Equal(EvidenceClass.Suspicious,
            EvidenceClassification.Classify(Ev("Heuristic", "Executável/script em Temp", 3, EvidenceStrength.Low)));
    }

    [Xunit.Fact]
    public void HasActionableCorroboration_OnlyForActionableOrConfirmed()
    {
        var technicalOnly = new List<Evidence>
        {
            Ev("PE", "Imports de injeção/process memory combinados: VirtualAlloc, OpenProcess", 4, EvidenceStrength.High),
            Ev("PE", "Resolução dinâmica de API (LoadLibrary/GetProcAddress)", 2, EvidenceStrength.Medium),
            Ev("Reputation", "Prevalência local estável", -4, EvidenceStrength.Info),
        };
        Xunit.Assert.False(EvidenceClassification.HasActionableCorroboration(technicalOnly));

        var withSevere = new List<Evidence>(technicalOnly) { Ev("PE", "Seção executável e gravável (RWX): .x", 4, EvidenceStrength.High) };
        Xunit.Assert.True(EvidenceClassification.HasActionableCorroboration(withSevere));

        var withConfirmed = new List<Evidence> { Ev("Reputation", "known bad", 100, EvidenceStrength.Confirmed, confirm: true) };
        Xunit.Assert.True(EvidenceClassification.HasActionableCorroboration(withConfirmed));
    }

    // ── Consistency with the 11C-stabilized actionable predicate (must not drift) ──

    [Xunit.Fact]
    public void EvidenceClassification_MatchesStabilizedScanEnginePredicate()
    {
        var lists = new[]
        {
            new List<Evidence> { Ev("PE", "Imports de injeção: VirtualAlloc, OpenProcess", 4, EvidenceStrength.High) },
            new List<Evidence> { Ev("PE", "Seção executável e gravável (RWX): .x", 4, EvidenceStrength.High) },
            new List<Evidence> { Ev("PE", "Correlação PE forte: indicadores", 4, EvidenceStrength.High) },
            new List<Evidence> { Ev("Reputation", "known bad", 100, EvidenceStrength.Confirmed, confirm: true) },
            new List<Evidence> { Ev("Heuristic", "Temp", 3, EvidenceStrength.Low) },
        };
        foreach (var l in lists)
            Xunit.Assert.Equal(
                ScanEngine.HasActionableEvidenceAfterTrustRecalibration(l),
                EvidenceClassification.HasActionableCorroboration(l));
    }
}
