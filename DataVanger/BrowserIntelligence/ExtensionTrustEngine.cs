using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Trust-aware scoring for browser extensions.
///
/// Combines:
///   - the browser context (do we even live inside a real browser profile?),
///   - the parsed manifest (permissions, MV2/MV3, CSP, native messaging…),
///   - the bundler footprint (webpack/vite/react → strong false-positive signal),
///   - the reputation database (well-known extension ids, prevalence).
///
/// Outputs an <see cref="ExtensionTrustEvaluation"/> with an explainable
/// list of reasons. NEVER emits CanConfirmMalware = true — this engine is
/// strictly heuristic by contract.
/// </summary>
public sealed class ExtensionTrustEngine
{
    private static readonly HashSet<string> WellKnownGoodExtensionIds = new(StringComparer.OrdinalIgnoreCase)
    {
        // Chromium "uBlock Origin"
        "cjpalhdlnbpafiamejdnhcphjbkeiagm",
        // 1Password
        "aeblfdkhhhdcdjpifhhbdiojplfjncoa",
        // Bitwarden
        "nngceckbapebfimnlniiiahkandclblb",
        // Grammarly
        "kbfnbcaeplbcioakkpcpgfkobkghlhen",
        // Google Translate
        "aapbdbdomjkkjkaonfhkkikfgjllcleb",
        // LastPass
        "hdokiejnpimakedhajhdlcegeplioahd",
        // React DevTools
        "fmkadmapgofadopljbjfkapdkoienihi",
        // Vue DevTools
        "nhdogjmejiglipccpnnnanhbledajbpd",
        // AdBlock Plus
        "cfhdojbkjhnklbpkdaibdccddilifddb",
        // Honey
        "bmnlcjabgnpnenekpadlanbbkooimhnj",
        // Dark Reader
        "eimadpbcbfnmbkopoojfekhnkhdbieeh",
    };

    public ExtensionTrustEvaluation Evaluate(ExtensionTrustInput input)
    {
        input ??= new ExtensionTrustInput();
        var reasons = new List<string>();
        var evidence = new List<Evidence>();
        int score = 0;
        var state = ExtensionTrustState.Unknown;

        // 1. Known-good extension id immediately downgrades.
        if (!string.IsNullOrEmpty(input.Context.ExtensionId)
            && WellKnownGoodExtensionIds.Contains(input.Context.ExtensionId))
        {
            score -= 8;
            state = ExtensionTrustState.Trusted;
            Add(reasons, evidence, $"Extension id reconhecido como amplamente confiável ({input.Context.ExtensionId})",
                -8, EvidenceStrength.Info);
        }

        // 2. Manifest hygiene
        if (input.Manifest.ParsedSuccessfully)
        {
            if (input.Manifest.ManifestVersion >= 3)
            {
                score -= 1;
                state = MoreTrusted(state, ExtensionTrustState.LikelyTrusted);
                Add(reasons, evidence, "Manifest V3: padrão moderno, sem APIs legadas mais arriscadas",
                    -1, EvidenceStrength.Info);
            }
            if (input.Manifest.UpdateUrl.Contains("clients2.google.com", StringComparison.OrdinalIgnoreCase)
                || input.Manifest.UpdateUrl.Contains("edge.microsoft.com", StringComparison.OrdinalIgnoreCase)
                || input.Manifest.UpdateUrl.Contains("addons.mozilla.org", StringComparison.OrdinalIgnoreCase)
                || input.Manifest.UpdateUrl.Contains("addons.opera.com", StringComparison.OrdinalIgnoreCase))
            {
                score -= 2;
                state = MoreTrusted(state, ExtensionTrustState.LikelyTrusted);
                Add(reasons, evidence, "update_url aponta para loja oficial do navegador", -2, EvidenceStrength.Info);
            }
        }
        else if (input.Context.IsExtensionContext)
        {
            // Failed to parse but the path says it should be an extension manifest.
            score += 1;
            state = MoreRisky(state, ExtensionTrustState.Suspicious);
            Add(reasons, evidence, $"manifest.json não pôde ser interpretado ({input.Manifest.ParseError})",
                1, EvidenceStrength.Low);
        }

        // 3. Permission risk profile
        var (high, moderate) = ClassifyPermissions(input.Manifest);
        if (high.Count > 0)
        {
            int delta = Math.Min(high.Count * 2, 5);
            score += delta;
            state = MoreRisky(state, ExtensionTrustState.Suspicious);
            Add(reasons, evidence,
                "Permissões de alto risco solicitadas: " + string.Join(", ", high),
                delta, EvidenceStrength.Medium);
        }
        if (moderate.Count >= 5)
        {
            score += 1;
            Add(reasons, evidence,
                $"Muitas permissões moderadas ({moderate.Count}): " + string.Join(", ", moderate.Take(8)),
                1, EvidenceStrength.Low);
        }

        // 4. Native messaging is a strong correlation signal.
        if (input.Manifest.Permissions.Any(p => p.Equals("nativeMessaging", StringComparison.OrdinalIgnoreCase))
            || input.Manifest.NativeMessagingHosts.Count > 0)
        {
            score += 2;
            state = MoreRisky(state, ExtensionTrustState.Suspicious);
            Add(reasons, evidence,
                "Extensão declara uso de native messaging — requer correlação com processos filhos do navegador",
                2, EvidenceStrength.Medium);
        }

        // 5. Remote code indicators — moderate by themselves, never confirming.
        if (input.Manifest.CspAllowsUnsafeEval)
        {
            score += 2;
            state = MoreRisky(state, ExtensionTrustState.Suspicious);
            Add(reasons, evidence, "CSP da extensão permite unsafe-eval", 2, EvidenceStrength.Medium);
        }
        if (input.Manifest.CspAllowsRemoteScript)
        {
            score += 2;
            state = MoreRisky(state, ExtensionTrustState.Suspicious);
            Add(reasons, evidence, "CSP da extensão libera scripts remotos via http(s)", 2, EvidenceStrength.Medium);
        }

        // 6. Side-loaded / developer mode in non-extension folder gets extra scrutiny.
        if (input.Context.IsSideLoadedPath)
        {
            score += 2;
            state = MoreRisky(state, ExtensionTrustState.Suspicious);
            Add(reasons, evidence,
                "Extensão sideloaded / instalada fora da loja oficial",
                2, EvidenceStrength.Medium);
        }

        // 7. Frontend bundle context — strong anti-false-positive signal.
        if (input.Bundle.IsRecognisedBundle)
        {
            int delta = input.Bundle.LooksLegitimatelyPackaged ? -5 : -2;
            score += delta;
            state = MoreTrusted(state, ExtensionTrustState.LikelyTrusted);
            Add(reasons, evidence,
                "Estrutura de bundle moderno detectada (" + string.Join(", ", input.Bundle.MarkersFound.Take(3))
                    + ") — reduz falsos positivos estáticos",
                delta, EvidenceStrength.Info);
        }
        else if (input.Bundle.LooksLegitimatelyPackaged)
        {
            score -= 2;
            state = MoreTrusted(state, ExtensionTrustState.LikelyTrusted);
            Add(reasons, evidence,
                "Pacote de extensão bem estruturado (_locales/_metadata/icons)",
                -2, EvidenceStrength.Info);
        }

        // 8. Local reputation prevalence
        if (input.LocalSeenCount >= 5)
        {
            score -= 3;
            state = MoreTrusted(state, ExtensionTrustState.LikelyTrusted);
            Add(reasons, evidence,
                $"Extensão observada localmente {input.LocalSeenCount} vezes — alta prevalência",
                -3, EvidenceStrength.Info);
        }

        // 9. WebAssembly alone is NOT malware.
        if (input.Bundle.WasmFileCount > 0 && state < ExtensionTrustState.Suspicious)
        {
            Add(reasons, evidence,
                "WebAssembly presente — neutro por si só, requer correlação para escalada",
                0, EvidenceStrength.Info);
        }

        // 10. Final state derivation from score when still unknown.
        if (state == ExtensionTrustState.Unknown)
        {
            state = score switch
            {
                <= -6 => ExtensionTrustState.Trusted,
                <= -2 => ExtensionTrustState.LikelyTrusted,
                >= 8  => ExtensionTrustState.HighRisk,
                >= 4  => ExtensionTrustState.Suspicious,
                _     => ExtensionTrustState.Unknown,
            };
        }

        // 11. Final anti-FP clamp: extension scoring never produces Critical-range scores.
        score = Math.Clamp(score, -10, RiskThresholds.High);

        return new ExtensionTrustEvaluation
        {
            TrustState = state,
            Score = score,
            Reasons = reasons,
            Evidence = evidence,
        };
    }

    private static (List<string> High, List<string> Moderate) ClassifyPermissions(ExtensionManifest manifest)
    {
        var high = new List<string>();
        var moderate = new List<string>();
        IEnumerable<string> All() =>
            manifest.Permissions.Concat(manifest.OptionalPermissions).Concat(manifest.HostPermissions);
        foreach (var p in All().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            switch (ExtensionPermissionCatalog.Classify(p))
            {
                case PermissionRiskLevel.High: high.Add(p); break;
                case PermissionRiskLevel.Moderate: moderate.Add(p); break;
            }
        }
        return (high, moderate);
    }

    private static void Add(List<string> reasons, List<Evidence> evidence, string description, int score, EvidenceStrength strength)
    {
        reasons.Add(description);
        evidence.Add(new Evidence
        {
            Category = "Browser",
            Description = description,
            ScoreDelta = score,
            Strength = strength,
            CanConfirmMalware = false,
        });
    }

    private static ExtensionTrustState MoreTrusted(ExtensionTrustState current, ExtensionTrustState candidate) =>
        (int)candidate < (int)current || current == ExtensionTrustState.Unknown ? candidate : current;

    private static ExtensionTrustState MoreRisky(ExtensionTrustState current, ExtensionTrustState candidate) =>
        (int)candidate > (int)current ? candidate : current;
}

public sealed class ExtensionTrustInput
{
    public BrowserContext Context { get; init; } = BrowserContext.None;
    public ExtensionManifest Manifest { get; init; } = new();
    public FrontendBundleProfile Bundle { get; init; } = new();
    public int LocalSeenCount { get; init; }
}

public sealed class ExtensionTrustEvaluation
{
    public ExtensionTrustState TrustState { get; init; } = ExtensionTrustState.Unknown;
    public int Score { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<Evidence> Evidence { get; init; } = Array.Empty<Evidence>();
}
