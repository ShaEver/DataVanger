using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DataVanger.Core;
using DataVanger.Detection.PE;

namespace DataVanger.Reputation;

public enum ReputationTrustState
{
    KnownGood,
    LikelyGood,
    Neutral,
    Unknown,
    Suspicious,
    HighRisk,
    KnownBad,
}

public enum ReputationUserDecision
{
    None,
    Allowed,
    Blocked,
    Quarantined,
    Restored,
}

public sealed class ReputationSubject
{
    public string? Sha256 { get; init; }
    public string Path { get; init; } = "";
    public string Extension { get; init; } = "";
    public long SizeKB { get; init; }
    public DateTime LastWriteUtc { get; init; }
    public int BaseScore { get; init; }
    public bool IsSigned { get; init; }
    public string Publisher { get; init; } = "";
    /// <summary>
    /// Certificate-backed trust decision from the scan-time Authenticode path.
    /// Null lets standalone reputation callers use their configured legacy
    /// name-only behavior; scan composition always supplies a value.
    /// </summary>
    public bool? PublisherTrusted { get; init; }
    public bool HasConfirmedEvidence { get; init; }
    public bool IsKnownMalicious { get; init; }
    public bool IsKnownSafe { get; init; }
    public bool IsUserAllowlisted { get; init; }
    public bool IsUserBlocklisted { get; init; }
    public IReadOnlyList<Evidence> Evidence { get; init; } = Array.Empty<Evidence>();
}

public sealed class ReputationEvaluation
{
    public ReputationTrustState TrustState { get; init; } = ReputationTrustState.Unknown;
    public int Score { get; init; }
    public int ScoreDelta { get; init; }
    public int AdjustedScore { get; init; }
    public ReputationUserDecision UserDecision { get; init; }
    public int SeenCount { get; init; }
    public DateTime? FirstSeenUtc { get; init; }
    public DateTime? LastSeenUtc { get; init; }
    public string SignerStatus { get; init; } = "Unknown";
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<Evidence> Evidence { get; init; } = Array.Empty<Evidence>();
}

public sealed class ReputationEngine
{
    private readonly SignatureDatabase _signatures;
    private readonly AppSettings _settings;

    public ReputationEngine(SignatureDatabase signatures, AppSettings settings)
    {
        _signatures = signatures ?? new SignatureDatabase();
        _settings = settings ?? new AppSettings();
    }

    public ReputationEvaluation Evaluate(ReputationSubject subject, LocalReputationEntry? previous)
    {
        subject ??= new ReputationSubject();
        var reasons = new List<string>();
        var evidence = new List<Evidence>();
        int score = 0;
        var state = ReputationTrustState.Unknown;
        var userDecision = ParseDecision(previous?.UserDecision);
        bool confirmed = subject.HasConfirmedEvidence || subject.IsKnownMalicious;
        bool userBlocked = subject.IsUserBlocklisted || userDecision is ReputationUserDecision.Blocked or ReputationUserDecision.Quarantined;
        bool userAllowed = subject.IsUserAllowlisted || userDecision == ReputationUserDecision.Allowed;
        bool knownBad = subject.IsKnownMalicious || subject.IsUserBlocklisted;
        bool knownGood = !knownBad && (subject.IsKnownSafe || subject.IsUserAllowlisted || previous?.WhitelistStatus == true);

        if (knownBad)
        {
            state = ReputationTrustState.KnownBad;
            score += 100;
            userDecision = subject.IsUserBlocklisted ? ReputationUserDecision.Blocked : userDecision;
            Add(reasons, evidence, "Hash conhecido como malicioso ou bloqueado pelo usuário", 100, EvidenceStrength.Confirmed, canConfirm: true);
        }
        else if (knownGood)
        {
            state = ReputationTrustState.KnownGood;
            score -= 80;
            userDecision = subject.IsUserAllowlisted ? ReputationUserDecision.Allowed : userDecision;
            Add(reasons, evidence, "Hash conhecido como confiável ou permitido pelo usuário", -80, EvidenceStrength.Info);
        }

        string signerStatus = subject.IsSigned ? "Signed" : "Unsigned";
        bool publisherTrusted = subject.PublisherTrusted
            ?? IsTrustedPublisher(subject.Publisher);
        if (!knownBad && subject.IsSigned && publisherTrusted)
        {
            signerStatus = "TrustedSigner";
            state = MoreTrusted(state, ReputationTrustState.LikelyGood);
            bool actionableEvidence = HasActionableEvidenceAfterTrustRecalibration(subject.Evidence);
            int trustedSignerDelta = confirmed || actionableEvidence ? 0 : -12;
            score += trustedSignerDelta;
            Add(reasons, evidence, $"Assinatura válida de fornecedor confiável: {subject.Publisher}", trustedSignerDelta, EvidenceStrength.Info);
        }
        else if (!subject.IsSigned && IsExecutableLike(subject.Extension) && IsUserWritablePath(subject.Path)
                 && !IsBenignVendorOrContainer(subject.Path))
        {
            score += 2;
            state = MoreRisky(state, ReputationTrustState.Suspicious);
            Add(reasons, evidence, "Executável sem assinatura em local gravável pelo usuário", 2, EvidenceStrength.Low);
        }

        if (!knownBad && previous?.BehavioralScore >= 6)
        {
            score += Math.Min(previous.BehavioralScore, 12);
            state = MoreRisky(state, ReputationTrustState.Suspicious);
            Add(reasons, evidence, "Histórico comportamental local suspeito", Math.Min(previous.BehavioralScore, 12), EvidenceStrength.Medium);
        }
        else if (!knownBad && !confirmed && previous?.BehavioralScore <= -4)
        {
            score -= 3;
            state = MoreTrusted(state, ReputationTrustState.LikelyGood);
            Add(reasons, evidence, "Histórico comportamental local limpo", -3, EvidenceStrength.Info);
        }
        int seen = Math.Max(0, previous?.SeenCount ?? 0);
        if (!knownBad && seen >= 20)
        {
            score -= confirmed ? 0 : 8;
            state = MoreTrusted(state, ReputationTrustState.LikelyGood);
            Add(reasons, evidence, $"Alta prevalência local: visto {seen} vezes", confirmed ? 0 : -8, EvidenceStrength.Info);
        }
        else if (!knownBad && seen >= 5)
        {
            score -= confirmed ? 0 : 4;
            state = MoreTrusted(state, ReputationTrustState.LikelyGood);
            Add(reasons, evidence, $"Prevalência local estável: visto {seen} vezes", confirmed ? 0 : -4, EvidenceStrength.Info);
        }
        else if (!knownGood && seen == 0 && IsRecentlyWritten(subject.LastWriteUtc) && IsExecutableLike(subject.Extension) && IsUserWritablePath(subject.Path))
        {
            score += 3;
            state = MoreRisky(state, ReputationTrustState.Suspicious);
            Add(reasons, evidence, "Primeira observação local recente em caminho de risco", 3, EvidenceStrength.Low);
        }

        if (!knownBad && IsBrowserExtensionContext(subject.Path))
        {
            bool weakStaticOnly = !confirmed && subject.Evidence.All(e =>
                e.Category.Equals("Browser", StringComparison.OrdinalIgnoreCase)
                || e.Category.Equals("Heuristic", StringComparison.OrdinalIgnoreCase)
                || e.Category.Equals("Script", StringComparison.OrdinalIgnoreCase)
                || e.Category.Equals("Reputation", StringComparison.OrdinalIgnoreCase));
            if (weakStaticOnly)
            {
                int delta = seen >= 2 || subject.Path.Contains("\\Extensions\\", StringComparison.OrdinalIgnoreCase) ? -8 : -4;
                score += delta;
                state = MoreTrusted(state, delta <= -8 ? ReputationTrustState.LikelyGood : ReputationTrustState.Neutral);
                Add(reasons, evidence, "Contexto legítimo de extensão de navegador reduz falso positivo estático", delta, EvidenceStrength.Info);
            }
        }

        if (userBlocked && !knownBad)
        {
            score += 12;
            state = MoreRisky(state, ReputationTrustState.HighRisk);
            Add(reasons, evidence, "Usuário marcou este hash como bloqueado/suspeito", 12, EvidenceStrength.High);
        }
        if (userAllowed && !knownBad)
        {
            int delta = confirmed ? -10 : -60;
            score += delta;
            state = confirmed ? MoreRisky(state, ReputationTrustState.HighRisk) : ReputationTrustState.KnownGood;
            Add(reasons, evidence, confirmed
                ? "Allowlist do usuário registrada, mas evidência confirmada ainda exige alerta"
                : "Allowlist do usuário reduz severidade de heurística estática", delta, EvidenceStrength.Info);
        }

        if (state == ReputationTrustState.Unknown)
            state = score switch
            {
                <= -40 => ReputationTrustState.KnownGood,
                <= -10 => ReputationTrustState.LikelyGood,
                >= 60 => ReputationTrustState.KnownBad,
                >= 14 => ReputationTrustState.HighRisk,
                >= 4 => ReputationTrustState.Suspicious,
                _ => ReputationTrustState.Neutral,
            };

        int deltaToApply = confirmed && score < 0 ? Math.Max(score, -10) : score;
        int adjusted = Math.Max(0, subject.BaseScore + deltaToApply);
        if (confirmed) adjusted = Math.Max(subject.BaseScore, adjusted);
        if (!confirmed && adjusted >= RiskThresholds.Critical) adjusted = RiskThresholds.High;

        return new ReputationEvaluation
        {
            TrustState = state,
            Score = Math.Clamp(score, -100, 100),
            ScoreDelta = deltaToApply,
            AdjustedScore = adjusted,
            UserDecision = userDecision,
            SeenCount = seen,
            FirstSeenUtc = previous?.FirstSeenUtc,
            LastSeenUtc = previous?.LastSeenUtc,
            SignerStatus = signerStatus,
            Reasons = reasons,
            Evidence = evidence,
        };
    }

    // Phase 11 / BETA 11D: routed through the PublisherIdentity evaluator using ANCHORED,
    // spoof-resistant name matching (a trusted name must start an RDN component, not appear
    // anywhere in the subject). Stronger validation modes fail closed on the name-only path.
    // The trusted-signer branch that calls this is already gated on !knownBad and its relief is
    // suppressed for confirmed evidence, so a trusted publisher can never override known-bad /
    // confirmed-malicious classification.
    private bool IsTrustedPublisher(string publisher)
        => DataVanger.Core.PublisherIdentity.IsTrustedPublisherName(publisher, _settings);

    private static bool HasActionableEvidenceAfterTrustRecalibration(IReadOnlyList<Evidence> evidence) =>
        evidence.Any(e =>
            e.ScoreDelta > 0
            && (e.CanConfirmMalware
                || e.Strength == EvidenceStrength.Confirmed
                || PeImportRecalibration.IsSevereStructuralEvidence(e)));

    private static void Add(List<string> reasons, List<Evidence> evidence, string description, int score, EvidenceStrength strength, bool canConfirm = false)
    {
        reasons.Add(description);
        evidence.Add(new Evidence
        {
            Category = "Reputation",
            Description = description,
            ScoreDelta = score,
            Strength = strength,
            CanConfirmMalware = canConfirm,
        });
    }

    private static ReputationUserDecision ParseDecision(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "allow" or "allowed" or "trusted" or "whitelist" => ReputationUserDecision.Allowed,
        "block" or "blocked" or "suspicious" or "blacklist" => ReputationUserDecision.Blocked,
        "quarantine" or "quarantined" => ReputationUserDecision.Quarantined,
        "restore" or "restored" => ReputationUserDecision.Restored,
        _ => ReputationUserDecision.None,
    };

    private static ReputationTrustState MoreTrusted(ReputationTrustState current, ReputationTrustState candidate) =>
        (int)candidate < (int)current || current == ReputationTrustState.Unknown ? candidate : current;

    private static ReputationTrustState MoreRisky(ReputationTrustState current, ReputationTrustState candidate) =>
        (int)candidate > (int)current ? candidate : current;

    private static bool IsExecutableLike(string ext) => ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".scr", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".com", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".js", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".bat", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".hta", StringComparison.OrdinalIgnoreCase);

    private static bool IsUserWritablePath(string path)
    {
        string p = path.ToLowerInvariant();
        return p.Contains("\\users\\") || p.Contains("\\appdata\\") || p.Contains("\\temp\\") || p.Contains("\\downloads\\") || p.Contains("\\desktop\\");
    }

    // Known dev/Electron containers and trusted vendor app dirs: an unsigned binary/script
    // there is benign noise (node_modules, vscode/claude extensions, Brave/Discord/Spotify
    // under LocalAppData, etc.). Reuses the same path vocabulary as the heuristic suppression.
    private static bool IsBenignVendorOrContainer(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string p = path.ToLowerInvariant();
        return DataVanger.Detection.PathTaxonomy.IsKnownBenignScriptContainer(p)
            || DataVanger.Detection.PathTaxonomy.IsTrustedPath(p);
    }

    private static bool IsBrowserExtensionContext(string path)
    {
        string p = path.ToLowerInvariant();
        return p.Contains("\\extensions\\")
            || p.Contains("\\browser extensions\\")
            || p.Contains("\\chrome\\user data\\")
            || p.Contains("\\edge\\user data\\")
            || p.Contains("\\firefox\\profiles\\")
            || Path.GetFileName(path).Equals("manifest.json", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRecentlyWritten(DateTime lastWriteUtc)
    {
        if (lastWriteUtc == default) return false;
        return DateTime.UtcNow - lastWriteUtc.ToUniversalTime() <= TimeSpan.FromDays(7);
    }
}
