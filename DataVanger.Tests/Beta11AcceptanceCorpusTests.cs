using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Detection;
using DataVanger.Detection.PE;
using DataVanger.Reputation;

// ============================================================================
// BETA 11F — FALSE-POSITIVE REGRESSION CORPUS (acceptance-gating).
//
// Locks in the BETA 11 behaviour: fewer false positives for trusted/system/
// signed files, WITHOUT introducing false negatives for confirmed or actionable
// malware. Every test maps to a BETA 11 root cause (RC-1..RC-7) and/or a sub-phase
// (11A catalog signatures, 11B system-path context, 11D publisher trust, 11C PE
// import recalibration, 11E actionable-tier separation). See the acceptance matrix
// in outputs/BETA_11F_ACCEPTANCE_MATRIX.md.
//
// The end-to-end cases use Compose(...), which mirrors the ScanEngine
// AnalyzeSingleFileAsync composition (11A->11E) using ONLY production functions in
// the engine's order — no reimplemented scoring. It is synthetic and deterministic
// (no real files, no network). Real-Windows behaviour is covered by the
// [WindowsOnlyFact] integration tests, which SKIP cleanly off-Windows.
// Filters: ~AntiFalsePositive, ~Detection, ~Pe, ~Publisher, ~Reputation, ~Scan, ~Classification.
// ============================================================================
public class Beta11AcceptanceCorpusTests
{
    // ---- canonical synthetic evidence (mirrors the production analyzer strings) ----
    private static Evidence Ev(string cat, string desc, int delta, EvidenceStrength s, bool confirm = false) =>
        new() { Category = cat, Description = desc, ScoreDelta = delta, Strength = s, CanConfirmMalware = confirm };

    private const string Injection = "Imports de injeção/process memory combinados: VirtualAlloc, OpenProcess";
    private const string NetExec = "Imports combinam rede e execução de processo: connect, system";
    private const string Dynamic = "Resolução dinâmica de API (LoadLibrary/GetProcAddress)";
    private const string Dpapi = "Imports relacionados a credenciais/DPAPI: CryptProtectData";
    private const string Persist = "Imports relacionados a persistência/serviços: RegSetValue, RegCreateKey";
    private const string AntiDbg = "Imports anti-debug/anti-análise: IsDebuggerPresent";
    private const string Rwx = "Seção executável e gravável (RWX): .evil";
    private const string PayloadMz = "Recurso contém payload com cabeçalho MZ";
    private const string EntryOut = "Entry point fora das seções mapeadas (RVA 0x9000)";
    private const string Forte = "Correlação PE forte: múltiplos indicadores estáticos de loader/injeção/empacotamento";
    private const string Timestamp = "Timestamp de compilação anômalo: 2097-04-23";
    private const string Masquerade = "Nome de processo de sistema (svchost.exe) fora de System32/SysWOW64 - possível mascaramento";
    private const string HiddenScript = "Execução oculta ou bypass de política";

    private static List<Evidence> ImportNoise() => new()
    {
        Ev("PE", Injection, 4, EvidenceStrength.High),
        Ev("PE", NetExec, 3, EvidenceStrength.Medium),
        Ev("PE", Dynamic, 2, EvidenceStrength.Medium),
        Ev("PE", Dpapi, 2, EvidenceStrength.Medium),
    };

    private readonly record struct CorpusResult(int Score, ThreatClass Tier, bool HasActionable, PublisherTrustLevel TrustLevel);

    /// <summary>
    /// Mirrors ScanEngine.AnalyzeSingleFileAsync (11A->11E) using production functions only:
    /// publisher-trust evaluation -> PE import recalibration -> actionable detection ->
    /// signed-publisher relief -> system-path relief -> reputation -> Critical clamp ->
    /// ThreatClassificationPolicy with the 11E context. Synthetic and deterministic.
    /// </summary>
    private static CorpusResult Compose(
        List<Evidence> evidence,
        bool isSigned = false, string publisher = "", SignatureSource source = SignatureSource.None,
        SystemPathKind systemKind = SystemPathKind.None,
        bool isKnownMalicious = false,
        string path = @"C:\Program Files\App\app.exe",
        AppSettings? settings = null)
    {
        settings ??= new AppSettings();

        var sig = new SignatureVerificationResult { IsSigned = isSigned, SignerSubject = publisher, Source = source };
        var trustLevel = PublisherIdentity.EvaluatePublisherTrust(sig, settings);
        bool trustedPublisher = trustLevel is PublisherTrustLevel.Trusted or PublisherTrustLevel.TrustedWindowsComponent;

        bool confirmedSig = evidence.Any(e => e.CanConfirmMalware
            && string.Equals(e.Category, "Signature", StringComparison.OrdinalIgnoreCase));

        int score = evidence.Sum(e => e.ScoreDelta); // preScore (before recalibration mutates the list)

        if (!isKnownMalicious && !confirmedSig)
        {
            int peReduction = PeImportRecalibration.Apply(evidence, trustLevel, systemKind);
            score = Math.Max(0, score - peReduction);
        }

        bool hasActionable = ScanEngine.HasActionableEvidenceAfterTrustRecalibration(evidence);

        if (!isKnownMalicious && !confirmedSig && isSigned)
            score = ScanEngine.ApplySignedPublisherRelief(score, trustedPublisher, hasActionable);

        if (!isKnownMalicious && !confirmedSig && score > 0)
            score = Math.Max(0, score - PathTaxonomy.SystemPathRelief(systemKind));

        var reputation = new ReputationEngine(new SignatureDatabase(), settings);
        var eval = reputation.Evaluate(new ReputationSubject
        {
            Sha256 = null,
            Path = path,
            Extension = System.IO.Path.GetExtension(path),
            SizeKB = 100,
            LastWriteUtc = DateTime.UtcNow,
            BaseScore = score,
            IsSigned = isSigned,
            Publisher = publisher,
            HasConfirmedEvidence = isKnownMalicious || confirmedSig || evidence.Any(e => e.CanConfirmMalware),
            IsKnownMalicious = isKnownMalicious,
            Evidence = evidence,
        }, null);
        score = eval.AdjustedScore;

        // Critical clamp (engine): unconfirmed heuristics never reach Critical.
        if (!isKnownMalicious && !confirmedSig && score >= RiskThresholds.Critical)
            score = RiskThresholds.High;

        bool trustedOrSystem = trustedPublisher || systemKind != SystemPathKind.None;
        var finding = new ScanFinding
        {
            Path = path,
            Score = score,
            IsBlacklisted = isKnownMalicious,
            HasConfirmedSignature = confirmedSig,
            TrustedOrSystemContext = trustedOrSystem,
            HasActionableCorroboration = hasActionable,
            Evidence = evidence.ToList(),
        };
        return new CorpusResult(score, ThreatClassificationPolicy.Classify(finding), hasActionable, trustLevel);
    }

    private static AppSettings TrustMicrosoft() => new() { TrustedPublishers = new List<string> { "Microsoft" } };

    // ===================== FALSE-POSITIVE REDUCTION (RC-1..RC-7) =====================

    [Xunit.Fact] // RC-1/RC-2 (11A) + RC-3 (11B) + RC-4 (11C)
    public void CatalogSignedSystem32_ImportsAlone_NotHighRisk()
    {
        var r = Compose(ImportNoise(), isSigned: true, publisher: "CN=Microsoft Windows, O=Microsoft Corporation",
            source: SignatureSource.Catalog, systemKind: SystemPathKind.System32,
            path: @"C:\Windows\System32\kerberos.dll", settings: TrustMicrosoft());

        Xunit.Assert.Equal(PublisherTrustLevel.TrustedWindowsComponent, r.TrustLevel);
        Xunit.Assert.NotEqual(ThreatClass.HighRisk, r.Tier);
        Xunit.Assert.NotEqual(ThreatClass.ConfirmedMalware, r.Tier);
    }

    [Xunit.Fact] // RC-1/RC-2 (11A) + RC-3 (11B)
    public void WinSxSCatalogSigned_ImportsAlone_NotHighRisk()
    {
        var r = Compose(ImportNoise(), isSigned: true, publisher: "CN=Microsoft Windows",
            source: SignatureSource.Catalog, systemKind: SystemPathKind.WinSxS,
            path: @"C:\Windows\WinSxS\amd64_x\tlscsp.dll", settings: TrustMicrosoft());

        Xunit.Assert.NotEqual(ThreatClass.HighRisk, r.Tier);
    }

    [Xunit.Fact] // RC-6 (11D) + RC-4 (11C)
    public void EmbeddedSignedTrustedApp_NormalImports_NotHighRisk()
    {
        var r = Compose(ImportNoise(), isSigned: true, publisher: "CN=Microsoft Corporation",
            source: SignatureSource.Embedded, systemKind: SystemPathKind.None,
            path: @"C:\Program Files\App\trusted.dll", settings: TrustMicrosoft());

        Xunit.Assert.Equal(PublisherTrustLevel.Trusted, r.TrustLevel);
        Xunit.Assert.NotEqual(ThreatClass.HighRisk, r.Tier);
    }

    [Xunit.Fact] // RC-6 (11D): valid-but-untrusted gets relief, not immunity
    public void ValidUntrustedApp_ImportsAlone_Relieved_NotHighRisk()
    {
        var r = Compose(ImportNoise(), isSigned: true, publisher: "CN=Contoso Ltd",
            source: SignatureSource.Embedded, systemKind: SystemPathKind.None);

        Xunit.Assert.Equal(PublisherTrustLevel.Valid, r.TrustLevel);
        Xunit.Assert.NotEqual(ThreatClass.HighRisk, r.Tier); // measured relief applied
    }

    [Xunit.Fact] // RC-4 (11C): API-heavy benign DLL, imports only
    public void ApiHeavyBenignUnsignedDll_ImportsAlone_NotHighRisk()
    {
        var ev = ImportNoise();
        ev.Add(Ev("PE", AntiDbg, 1, EvidenceStrength.Low));
        ev.Add(Ev("PE", Persist, 2, EvidenceStrength.Low)); // import sum = 14
        var r = Compose(ev, isSigned: false, systemKind: SystemPathKind.None,
            path: @"C:\Program Files\Vendor\heavy.dll");

        Xunit.Assert.NotEqual(ThreatClass.HighRisk, r.Tier); // capped to 8 -> Suspect
    }

    [Xunit.Fact] // RC-5 (11C): deterministic/future timestamp in trusted/system context
    public void DeterministicTimestamp_TrustedSystem_NotStrongRisk()
    {
        var ev = new List<Evidence>
        {
            Ev("PE", Timestamp, 1, EvidenceStrength.Low),
            Ev("PE", Injection, 4, EvidenceStrength.High),
        };
        var r = Compose(ev, isSigned: false, systemKind: SystemPathKind.System32,
            path: @"C:\Windows\System32\x.dll");

        Xunit.Assert.NotEqual(ThreatClass.HighRisk, r.Tier);
        Xunit.Assert.Contains(ev, e => e.Description.Contains("Timestamp") && e.ScoreDelta == 0); // demoted
    }

    // ===================== FALSE-NEGATIVE PREVENTION (anti-FN controls) =====================

    [Xunit.Fact] // 11C+11E: trusted relief must NOT erase severe PE evidence
    public void TrustedSigned_WithSevereAnomalies_StaysHighRisk()
    {
        var ev = new List<Evidence>
        {
            Ev("PE", Rwx, 4, EvidenceStrength.High),
            Ev("PE", PayloadMz, 4, EvidenceStrength.High),
            Ev("PE", EntryOut, 4, EvidenceStrength.High),
            Ev("PE", Injection, 4, EvidenceStrength.High),
        };
        var r = Compose(ev, isSigned: true, publisher: "CN=Microsoft Corporation",
            source: SignatureSource.Embedded, systemKind: SystemPathKind.None, settings: TrustMicrosoft());

        Xunit.Assert.True(r.HasActionable, "Severe PE anomalies must count as actionable corroboration.");
        Xunit.Assert.Equal(ThreatClass.HighRisk, r.Tier); // relief never erased the severe evidence
        Xunit.Assert.Contains(ev, e => e.Description.Contains("(RWX)") && e.ScoreDelta == 4);
    }

    [Xunit.Fact] // RC-6 (11D): valid-untrusted is relief, NOT immunity, against severe evidence
    public void ValidUntrusted_WithSevereAnomalies_StaysHighRisk()
    {
        var ev = new List<Evidence>
        {
            Ev("PE", Rwx, 4, EvidenceStrength.High),
            Ev("PE", PayloadMz, 4, EvidenceStrength.High),
            Ev("PE", EntryOut, 4, EvidenceStrength.High),
            Ev("PE", Injection, 4, EvidenceStrength.High),
        };
        var r = Compose(ev, isSigned: true, publisher: "CN=Contoso Ltd", source: SignatureSource.Embedded);

        Xunit.Assert.Equal(ThreatClass.HighRisk, r.Tier); // -6 relief is bounded, not immunity
    }

    [Xunit.Fact] // 11C cap does not protect unsigned files in user-writable paths
    public void UnsignedSuspicious_UserWritable_CanReachHighRisk()
    {
        var ev = ImportNoise();
        ev.Add(Ev("PE", AntiDbg, 1, EvidenceStrength.Low));
        ev.Add(Ev("PE", Persist, 2, EvidenceStrength.Low));     // imports = 14
        ev.Add(Ev("Script", HiddenScript, 3, EvidenceStrength.Medium));
        var r = Compose(ev, isSigned: false, systemKind: SystemPathKind.None,
            path: @"C:\Users\sonic\AppData\Local\Temp\dropper.exe");

        Xunit.Assert.Equal(ThreatClass.HighRisk, r.Tier);
    }

    [Xunit.Fact] // masquerade stays suspicious and is NOT protected by trust/system gating
    public void MasqueradingFile_RemainsAtLeastSuspect_NotGated()
    {
        var ev = new List<Evidence> { Ev("Heuristic", Masquerade, 7, EvidenceStrength.High) };
        var r = Compose(ev, isSigned: false, systemKind: SystemPathKind.None,
            path: @"C:\Users\sonic\AppData\Local\Temp\svchost.exe");

        Xunit.Assert.NotEqual(ThreatClass.Clean, r.Tier);
        Xunit.Assert.True(r.Tier is ThreatClass.Suspect or ThreatClass.HighRisk);
    }

    // ===================== CONFIRMED MALWARE OVERRIDES & CLAMP =====================

    [Xunit.Fact] // known-malicious hash beats all trust/system gating
    public void KnownMaliciousHash_InTrustedSystemContext_IsConfirmedMalware()
    {
        var r = Compose(ImportNoise(), isSigned: true, publisher: "CN=Microsoft Windows",
            source: SignatureSource.Catalog, systemKind: SystemPathKind.System32,
            isKnownMalicious: true, path: @"C:\Windows\System32\evil.dll", settings: TrustMicrosoft());

        Xunit.Assert.Equal(ThreatClass.ConfirmedMalware, r.Tier);
    }

    [Xunit.Fact] // confirmed YARA beats all trust/system gating
    public void ConfirmedYara_InTrustedSystemContext_IsConfirmedMalware()
    {
        var ev = ImportNoise();
        ev.Add(Ev("Signature", "Regra YARA confirmada", 50, EvidenceStrength.Confirmed, confirm: true));
        var r = Compose(ev, isSigned: true, publisher: "CN=Microsoft Windows",
            source: SignatureSource.Catalog, systemKind: SystemPathKind.System32, settings: TrustMicrosoft());

        Xunit.Assert.Equal(ThreatClass.ConfirmedMalware, r.Tier);
    }

    [Xunit.Fact] // unconfirmed heuristics never reach ConfirmedMalware (Critical clamp)
    public void HighUnconfirmedScore_ClampsToHighRisk_NotConfirmedMalware()
    {
        var ev = new List<Evidence>
        {
            Ev("PE", Rwx, 4, EvidenceStrength.High),
            Ev("PE", PayloadMz, 4, EvidenceStrength.High),
            Ev("PE", EntryOut, 4, EvidenceStrength.High),
            Ev("PE", Forte, 4, EvidenceStrength.High),
            Ev("Heuristic", "Sinal forte", 4, EvidenceStrength.High), // sum = 20, unconfirmed
        };
        var r = Compose(ev, isSigned: false, path: @"C:\Program Files\App\app.exe");

        Xunit.Assert.NotEqual(ThreatClass.ConfirmedMalware, r.Tier);
        Xunit.Assert.Equal(ThreatClass.HighRisk, r.Tier);

        // Direct clamp coverage:
        var unconfirmed = new ScanFinding { Score = 20 };
        Xunit.Assert.Equal(RiskThresholds.High, AntiFalsePositivePolicy.ClampToHighRiskWhenUnconfirmed(20, unconfirmed));
        var confirmed = new ScanFinding { Score = 20, IsBlacklisted = true };
        Xunit.Assert.Equal(20, AntiFalsePositivePolicy.ClampToHighRiskWhenUnconfirmed(20, confirmed));
    }

    [Xunit.Fact] // automatic quarantine remains ConfirmedMalware-only
    public void AutomaticAction_OnlyForConfirmedMalware()
    {
        var confirmed = new ScanFinding { Score = 12, IsBlacklisted = true };
        var highRisk = new ScanFinding { Score = 12 };
        var gatedSuspect = new ScanFinding { Score = 12, TrustedOrSystemContext = true, HasActionableCorroboration = false };

        Xunit.Assert.True(ThreatClassificationPolicy.AllowsAutomaticAction(confirmed));
        Xunit.Assert.False(ThreatClassificationPolicy.AllowsAutomaticAction(highRisk));
        Xunit.Assert.False(ThreatClassificationPolicy.AllowsAutomaticAction(gatedSuspect));
    }

    // ===================== 11E tier gating (trusted/system technical-only) =====================

    [Xunit.Fact] // 11E: trusted/system file, only technical/info evidence -> gated to Suspect
    public void TrustedSystem_TechnicalImportsOnly_GatedBelowHighRisk()
    {
        // System32, unsigned (catalog unavailable): imports are demoted, but even if residual
        // technical/info evidence summed high, the 11E gate keeps it out of HighRisk without an
        // actionable signal.
        var ev = ImportNoise();
        ev.Add(Ev("Heuristic", "DLL fora de pasta de sistema", 2, EvidenceStrength.Medium));
        var r = Compose(ev, isSigned: false, systemKind: SystemPathKind.System32,
            path: @"C:\Windows\System32\noise.dll");

        Xunit.Assert.False(r.HasActionable);
        Xunit.Assert.NotEqual(ThreatClass.HighRisk, r.Tier);
    }

    // ===================== Windows-only integration (real catalog/system files) =====================

    [WindowsOnlyFact] // 11A+11D on a real signed System32 component
    public void Integration_RealSystem32Component_IsSignedAndTrusted()
    {
        string dll = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
        if (!System.IO.File.Exists(dll)) return;

        var sig = WinTrust.VerifySignature(dll);
        Xunit.Assert.True(sig.IsSigned, "A core System32 component must verify as signed (embedded or catalog).");

        var level = PublisherIdentity.EvaluatePublisherTrust(sig, TrustMicrosoft());
        Xunit.Assert.True(level is PublisherTrustLevel.Trusted or PublisherTrustLevel.TrustedWindowsComponent,
            "A signed Microsoft System32 component must map to trusted publisher / Windows component.");
    }

    [WindowsOnlyFact] // 11B: a real System32 path classifies as a protected system location
    public void Integration_RealSystem32Path_ClassifiesAsSystem()
    {
        string dll = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
        var kind = PathTaxonomy.ClassifySystemPath(dll.ToLowerInvariant());
        Xunit.Assert.Equal(SystemPathKind.System32, kind);
    }
}
