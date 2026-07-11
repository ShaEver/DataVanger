using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

/// <summary>
/// BETA 11C — trust-aware recalibration of common PE import evidence. Ordinary
/// technical imports (allocation/process, dynamic API resolution, network+exec,
/// DPAPI, registry/service, anti-debug) are extremely common in legitimate Windows
/// DLLs, installers, launchers and Electron/CEF apps, yet they can stack to push a
/// benign file into HighRisk by themselves. This pass:
///
///   * for LOW-trust files (unsigned / invalid / valid-but-untrusted, non-system):
///     caps the cumulative common-import contribution so imports ALONE cannot reach
///     HighRisk — reputation/path/severe evidence still add on top;
///   * for STRONG-trust files (trusted publisher / catalog Windows component / genuine
///     system path from 11B): demotes common imports (and a deterministic/far-future
///     timestamp, unless a severe anomaly is present) to informational.
///
/// It NEVER touches severe/structural anomalies (RWX, packer, embedded MZ payload,
/// entry-point outside sections, strong correlation, executable high-entropy), never
/// runs on confirmed malware (the caller gates on !isKnownMalware &amp;&amp;
/// !hasConfirmedSignature), and never changes a risk threshold or the Critical clamp.
/// It returns the score reduction the caller subtracts, and adds one explanatory
/// (ScoreDelta = 0) evidence line for auditability.
/// </summary>
internal static class PeImportRecalibration
{
    /// <summary>Common imports alone may never reach the HighRisk threshold (9) for low-trust files.</summary>
    internal const int WeakImportCap = 8;

    internal static int Apply(IList<Evidence> evidence, PublisherTrustLevel trustLevel, SystemPathKind systemKind)
    {
        if (evidence is null || evidence.Count == 0) return 0;

        bool strong = trustLevel is PublisherTrustLevel.Trusted or PublisherTrustLevel.TrustedWindowsComponent
                      || systemKind != SystemPathKind.None;
        // A valid Authenticode signature (even from an untrusted publisher) makes the file
        // accountable; combined with NO hard anomaly it is treated as a signed installer.
        bool signed = strong || trustLevel == PublisherTrustLevel.Valid;
        bool hasSevere = evidence.Any(IsSevereStructuralEvidence);
        // Hard anomalies (RWX/packer/entry-point/exec-entropy/exec-without-raw) are NEVER
        // relieved and gate the signed-structural relief: if any is present the file stays
        // fully actionable regardless of signature (anti-false-negative).
        bool hasHardSevere = evidence.Any(e => IsPe(e) && IsHardSevere(e.Description));

        int reduction = 0;
        if (strong)
        {
            foreach (var e in evidence)
            {
                if (!IsPe(e) || e.ScoreDelta <= 0) continue;
                bool demote = IsCommonImportEvidence(e)
                              || (IsTimestampAnomaly(e.Description) && !hasSevere);
                if (!demote) continue;
                reduction += e.ScoreDelta;
                e.ScoreDelta = 0;
                e.Strength = EvidenceStrength.Info;
                e.Description = "[contexto confiável/sistema] " + e.Description;
            }
        }
        else
        {
            int importSum = evidence.Where(IsCommonImportEvidence).Sum(e => e.ScoreDelta);
            if (importSum > WeakImportCap) reduction = importSum - WeakImportCap;
        }

        // Signed installer/bundler relief: an embedded MZ payload in a resource (and the
        // strong correlation derived from it) is extremely common in legitimately signed
        // installers/launchers. For SIGNED files with NO hard anomaly, demote those two
        // signals so the signature relief can apply. Unsigned/invalid files, and any file
        // that ALSO has a hard anomaly, are untouched.
        if (signed && !hasHardSevere)
        {
            foreach (var e in evidence)
            {
                if (!IsPe(e) || e.ScoreDelta <= 0) continue;
                if (!IsSignedRelievableStructural(e.Description)) continue;
                reduction += e.ScoreDelta;
                e.ScoreDelta = 0;
                e.Strength = EvidenceStrength.Info;
                e.Description = "[instalador assinado] " + e.Description;
            }
        }

        if (reduction > 0)
        {
            evidence.Add(new Evidence
            {
                Category = "PE",
                Description = strong
                    ? $"Imports comuns reclassificados como informativos por contexto de confiança/sistema (-{reduction})"
                    : $"Contribuição de imports comuns limitada a {WeakImportCap} (-{reduction})",
                ScoreDelta = 0,
                Strength = EvidenceStrength.Info,
                CanConfirmMalware = false,
            });
        }
        return reduction;
    }

    internal static bool IsCommonImportEvidence(Evidence e) =>
        IsPe(e) && IsNormalImport(e.Description);

    internal static bool IsSevereStructuralEvidence(Evidence e) =>
        IsPe(e) && IsSevereStructural(e.Description);

    private static bool IsPe(Evidence e) => string.Equals(e.Category, "PE", StringComparison.OrdinalIgnoreCase);

    // Common technical imports (and moderate correlation, which is derived from them).
    private static bool IsNormalImport(string d) =>
        d.StartsWith("Imports ", StringComparison.OrdinalIgnoreCase)
        || d.StartsWith("Import sensível", StringComparison.OrdinalIgnoreCase)
        || d.StartsWith("Resolução dinâmica de API", StringComparison.OrdinalIgnoreCase)
        || d.StartsWith("Tabela de imports", StringComparison.OrdinalIgnoreCase)
        || d.StartsWith("Correlação PE moderada", StringComparison.OrdinalIgnoreCase);

    private static bool IsTimestampAnomaly(string d) =>
        d.StartsWith("Timestamp de compilação anômalo", StringComparison.OrdinalIgnoreCase);

    // Full severe/structural set. Semantics unchanged: this is what
    // HasActionableEvidenceAfterTrustRecalibration consults, so for UNSIGNED files the
    // embedded-MZ-payload and strong-correlation signals remain severe/actionable.
    private static bool IsSevereStructural(string d) =>
        IsHardSevere(d) || IsSignedRelievableStructural(d);

    // Hard anomalies — never relieved for anyone (signed or not), and they gate the
    // signed-installer relief above.
    private static bool IsHardSevere(string d) =>
        d.Contains("(RWX)", StringComparison.OrdinalIgnoreCase)
        || d.Contains("packer", StringComparison.OrdinalIgnoreCase)
        || d.StartsWith("Entry point fora", StringComparison.OrdinalIgnoreCase)
        || d.StartsWith("Alta entropia em seção executável", StringComparison.OrdinalIgnoreCase)
        || d.StartsWith("Seção executável sem dados brutos", StringComparison.OrdinalIgnoreCase);

    // Structural signals common in signed installers/bundlers (an embedded PE in a
    // resource, and the strong correlation derived from it). Relieved for SIGNED files
    // ONLY when no hard anomaly is present; always severe for unsigned files.
    private static bool IsSignedRelievableStructural(string d) =>
        d.StartsWith("Correlação PE forte", StringComparison.OrdinalIgnoreCase)
        || d.Contains("payload com cabeçalho MZ", StringComparison.OrdinalIgnoreCase)
        || d.Contains("payload PE embutido", StringComparison.OrdinalIgnoreCase);
}
