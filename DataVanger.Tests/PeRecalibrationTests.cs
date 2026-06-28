using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;
using DataVanger.Detection;
using DataVanger.Detection.PE;
using DataVanger.Reputation;

// BETA 11C — trust-aware PE import recalibration + correlation tightening.
// Anti-FP: common imports cannot push low-trust files to HighRisk by themselves and
// are demoted for trusted/system files. Anti-FN: severe structural anomalies (RWX,
// packer, embedded payload, entry-point, strong correlation) are NEVER attenuated.
// Filters: ~Pe, ~Detection, ~AntiFalsePositive.
public class PeRecalibrationTests
{
    private static Evidence Pe(string desc, int delta, EvidenceStrength s = EvidenceStrength.Medium) =>
        new() { Category = "PE", Description = desc, ScoreDelta = delta, Strength = s };

    private const string Injection = "Imports de injeção/process memory combinados: VirtualAlloc, OpenProcess";
    private const string NetExec = "Imports combinam rede e execução de processo: connect, system";
    private const string Dynamic = "Resolução dinâmica de API (LoadLibrary/GetProcAddress)";
    private const string Dpapi = "Imports relacionados a credenciais/DPAPI: CryptProtectData";
    private const string Rwx = "Seção executável e gravável (RWX): .evil";
    private const string Forte = "Correlação PE forte: múltiplos indicadores estáticos de loader/injeção/empacotamento";
    private const string Moderada = "Correlação PE moderada: indicadores estáticos combinados";
    private const string Timestamp = "Timestamp de compilação anômalo: 2097-04-23";
    private const string Mz = "Recurso contém payload com cabeçalho MZ";

    // ── Low-trust cap: imports alone cannot reach HighRisk ──

    [Xunit.Fact]
    public void Weak_CapsCommonImports_PreservesSevereRwx()
    {
        var ev = new List<Evidence>
        {
            Pe(Injection, 4, EvidenceStrength.High),
            Pe(NetExec, 3),
            Pe(Dynamic, 2),
            Pe(Dpapi, 2),                       // import sum = 11
            Pe(Rwx, 4, EvidenceStrength.High),  // severe — must be untouched
        };

        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Unsigned, SystemPathKind.None);

        Xunit.Assert.Equal(11 - PeImportRecalibration.WeakImportCap, reduction); // 11 - 8 = 3
        Xunit.Assert.Contains(ev, e => e.Description.Contains("(RWX)") && e.ScoreDelta == 4 && e.Strength == EvidenceStrength.High);
        Xunit.Assert.Contains(ev, e => e.Description.StartsWith("Imports de injeção") && e.ScoreDelta == 4); // not demoted in weak
        Xunit.Assert.Contains(ev, e => e.Description.Contains("limitada") && e.ScoreDelta == 0);
    }

    [Xunit.Fact]
    public void Weak_NoCap_WhenImportsUnderThreshold()
    {
        var ev = new List<Evidence>
        {
            Pe("Imports anti-debug/anti-análise: IsDebuggerPresent", 1, EvidenceStrength.Low),
            Pe("Imports de rede presentes: connect", 1, EvidenceStrength.Low),
        };
        Xunit.Assert.Equal(0, PeImportRecalibration.Apply(ev, PublisherTrustLevel.Valid, SystemPathKind.None));
    }

    // ── Strong trust/system: demote common imports, preserve severe ──

    [Xunit.Fact]
    public void Strong_System_DemotesImportsAndModerateCorrelation_KeepsRwx_AndTimestampWhenSevere()
    {
        var ev = new List<Evidence>
        {
            Pe(Injection, 4, EvidenceStrength.High),
            Pe(NetExec, 3),
            Pe(Dynamic, 2),
            Pe(Moderada, 2),
            Pe(Timestamp, 1, EvidenceStrength.Low),
            Pe(Rwx, 4, EvidenceStrength.High), // severe present → timestamp stays
        };

        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Unsigned, SystemPathKind.System32);

        // injection 4 + netexec 3 + dynamic 2 + moderada 2 = 11 (timestamp NOT demoted, severe present)
        Xunit.Assert.Equal(11, reduction);
        Xunit.Assert.Contains(ev, e => e.Description.Contains("injeção") && e.ScoreDelta == 0 && e.Strength == EvidenceStrength.Info);
        Xunit.Assert.Contains(ev, e => e.Description.Contains("moderada") && e.ScoreDelta == 0);
        Xunit.Assert.Contains(ev, e => e.Description.Contains("Timestamp") && e.ScoreDelta == 1);      // kept (severe present)
        Xunit.Assert.Contains(ev, e => e.Description.Contains("(RWX)") && e.ScoreDelta == 4 && e.Strength == EvidenceStrength.High);
        Xunit.Assert.Contains(ev, e => e.Description.Contains("reclassificados"));
    }

    [Xunit.Fact]
    public void Strong_Trusted_DemotesTimestamp_WhenNoSevere()
    {
        var ev = new List<Evidence>
        {
            Pe(Injection, 4, EvidenceStrength.High),
            Pe(Timestamp, 1, EvidenceStrength.Low),
        };

        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.TrustedWindowsComponent, SystemPathKind.None);

        Xunit.Assert.Equal(5, reduction); // 4 + 1, no severe → timestamp demoted
        Xunit.Assert.Contains(ev, e => e.Description.Contains("Timestamp") && e.ScoreDelta == 0);
    }

    [Xunit.Fact]
    public void Strong_NeverDemotes_ForteCorrelation()
    {
        var ev = new List<Evidence>
        {
            Pe(Forte, 4, EvidenceStrength.High),
            Pe(Injection, 4, EvidenceStrength.High),
        };

        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Unsigned, SystemPathKind.WinSxS);

        Xunit.Assert.Equal(4, reduction); // only the injection import demoted
        Xunit.Assert.Contains(ev, e => e.Description.Contains("Correlação PE forte") && e.ScoreDelta == 4 && e.Strength == EvidenceStrength.High);
    }

    [Xunit.Fact]
    public void TrustedPublisherRelief_DoesNotZeroSeverePeEvidence_AfterImportDemotion()
    {
        var ev = new List<Evidence>
        {
            Pe(Injection, 4, EvidenceStrength.High),
            Pe(Rwx, 4, EvidenceStrength.High),
            Pe(Forte, 4, EvidenceStrength.High),
        };
        int score = ev.Sum(e => e.ScoreDelta);

        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Trusted, SystemPathKind.None);
        score = ScanEngine.ApplySignedPublisherRelief(
            score - reduction,
            trustedPublisher: true,
            hasActionableEvidence: ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev));

        Xunit.Assert.Equal(4, reduction);
        Xunit.Assert.Equal(8, score);
        Xunit.Assert.True(ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev));
    }

    [Xunit.Fact]
    public void TrustedPublisherRelief_StillZerosCommonImportNoise()
    {
        var ev = new List<Evidence>
        {
            Pe(Injection, 4, EvidenceStrength.High),
            Pe(Dynamic, 2),
        };
        int score = ev.Sum(e => e.ScoreDelta);

        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Trusted, SystemPathKind.None);
        score = ScanEngine.ApplySignedPublisherRelief(
            score - reduction,
            trustedPublisher: true,
            hasActionableEvidence: ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev));

        Xunit.Assert.Equal(6, reduction);
        Xunit.Assert.Equal(0, score);
        Xunit.Assert.False(ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev));
    }

    [Xunit.Fact]
    public void ReputationTrustedSigner_DoesNotSubtractSeverePeEvidence()
    {
        var ev = new List<Evidence>
        {
            Pe(Injection, 4, EvidenceStrength.High),
            Pe(Rwx, 4, EvidenceStrength.High),
            Pe(Forte, 4, EvidenceStrength.High),
        };
        int score = ev.Sum(e => e.ScoreDelta);
        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Trusted, SystemPathKind.None);
        var engine = new ReputationEngine(new SignatureDatabase(), new AppSettings
        {
            TrustedPublishers = new List<string> { "Microsoft" },
        });

        var eval = engine.Evaluate(new ReputationSubject
        {
            Path = @"C:\Program Files\Microsoft\tool.exe",
            Extension = ".exe",
            BaseScore = score - reduction,
            IsSigned = true,
            Publisher = "CN=Microsoft Corporation",
            PublisherTrusted = true,
            LastWriteUtc = System.DateTime.UtcNow.AddDays(-30),
            Evidence = ev,
        }, null);

        Xunit.Assert.Equal(score - reduction, eval.AdjustedScore);
        Xunit.Assert.Contains(eval.Evidence, e => e.Category == "Reputation" && e.ScoreDelta == 0);
    }

    [Xunit.Fact]
    public void EmptyEvidence_IsSafe()
    {
        Xunit.Assert.Equal(0, PeImportRecalibration.Apply(new List<Evidence>(), PublisherTrustLevel.Unsigned, SystemPathKind.None));
    }

    // ── Signed installer/bundler relief: embedded MZ payload + strong correlation ──
    // (the dominant driver of signed false positives — installers/launchers embed a PE
    //  in a resource). Relieved for SIGNED files ONLY when no hard anomaly is present.

    [Xunit.Fact]
    public void SignedValidInstaller_MzPayloadAndForte_NoHardAnomaly_IsRelieved_NotActionable()
    {
        var ev = new List<Evidence>
        {
            Pe(Forte, 4, EvidenceStrength.High),
            Pe(Mz, 4, EvidenceStrength.High),
            Pe(Injection, 4, EvidenceStrength.High),
            Pe(Dynamic, 2),
        };
        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Valid, SystemPathKind.None);

        Xunit.Assert.True(reduction >= 8, $"MZ payload + strong correlation must be demoted for signed installers; got {reduction}.");
        Xunit.Assert.Contains(ev, e => e.Description.Contains("cabeçalho MZ") && e.ScoreDelta == 0);
        Xunit.Assert.Contains(ev, e => e.Description.Contains("Correlação PE forte") && e.ScoreDelta == 0);
        Xunit.Assert.False(ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev),
            "With MZ/forte demoted and no hard anomaly, a signed installer is not actionable.");
    }

    [Xunit.Fact]
    public void SignedTrustedInstaller_MzPayloadAndForte_ReliefZerosScore()
    {
        var ev = new List<Evidence> { Pe(Forte, 4, EvidenceStrength.High), Pe(Mz, 4, EvidenceStrength.High) };
        int score = ev.Sum(e => e.ScoreDelta);
        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Trusted, SystemPathKind.None);
        bool actionable = ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev);
        score = ScanEngine.ApplySignedPublisherRelief(score - reduction, trustedPublisher: true, hasActionableEvidence: actionable);

        Xunit.Assert.False(actionable);
        Xunit.Assert.Equal(0, score);
    }

    [Xunit.Fact] // anti-FN: UNSIGNED files keep MZ-payload / strong-correlation actionable
    public void Unsigned_MzPayloadAndForte_StaysActionable_NotRelieved()
    {
        var ev = new List<Evidence> { Pe(Forte, 4, EvidenceStrength.High), Pe(Mz, 4, EvidenceStrength.High) };
        int reduction = PeImportRecalibration.Apply(ev, PublisherTrustLevel.Unsigned, SystemPathKind.None);

        Xunit.Assert.Equal(0, reduction);
        Xunit.Assert.Contains(ev, e => e.Description.Contains("cabeçalho MZ") && e.ScoreDelta == 4);
        Xunit.Assert.True(ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev),
            "Unsigned files keep embedded-MZ-payload / strong-correlation as actionable.");
    }

    [Xunit.Fact] // anti-FN: a hard anomaly (RWX) on a SIGNED file blocks the installer relief
    public void SignedValid_WithHardAnomaly_DoesNotRelieveMzOrForte()
    {
        var ev = new List<Evidence>
        {
            Pe(Rwx, 4, EvidenceStrength.High),
            Pe(Mz, 4, EvidenceStrength.High),
            Pe(Forte, 4, EvidenceStrength.High),
        };
        PeImportRecalibration.Apply(ev, PublisherTrustLevel.Valid, SystemPathKind.None);

        Xunit.Assert.Contains(ev, e => e.Description.Contains("cabeçalho MZ") && e.ScoreDelta == 4);
        Xunit.Assert.Contains(ev, e => e.Description.StartsWith("Correlação PE forte") && e.ScoreDelta == 4);
        Xunit.Assert.True(ScanEngine.HasActionableEvidenceAfterTrustRecalibration(ev));
    }

    // ── Correlation tightening: "forte" requires a structural signal ──

    private static PeFile MakePe(IEnumerable<string> imports, IEnumerable<PeSection>? sections = null)
    {
        var pe = new PeFile { Length = 4096 };
        foreach (var i in imports) pe.Imports.Add(i);
        pe.ImportCount = pe.Imports.Count;
        if (sections != null) pe.Sections.AddRange(sections);
        return pe;
    }

    [Xunit.Fact]
    public void Correlation_ThreeImportOnlySignals_AreModerate_NotForte()
    {
        // injection (VirtualAlloc+OpenProcess) + dynamic (LoadLibrary+GetProcAddress) + network/exec (connect+system)
        var pe = MakePe(new[] { "VirtualAlloc", "OpenProcess", "LoadLibraryA", "GetProcAddress", "connect", "system" });
        var res = new PeAnalysisResult { File = pe };

        PeCorrelationEngine.Analyze(res);

        Xunit.Assert.Contains(res.Evidence, e => e.Description.Contains("Correlação PE moderada"));
        Xunit.Assert.DoesNotContain(res.Evidence, e => e.Description.Contains("Correlação PE forte"));
    }

    [Xunit.Fact]
    public void Correlation_WithStructuralSignal_IsForte()
    {
        var rwx = new PeSection { Name = ".x", Characteristics = PeSection.Read | PeSection.Write | PeSection.Execute };
        var pe = MakePe(new[] { "VirtualAlloc", "OpenProcess", "LoadLibraryA", "GetProcAddress" }, new[] { rwx });
        var res = new PeAnalysisResult { File = pe };

        PeCorrelationEngine.Analyze(res);

        Xunit.Assert.Contains(res.Evidence, e => e.Description.Contains("Correlação PE forte"));
    }
}
