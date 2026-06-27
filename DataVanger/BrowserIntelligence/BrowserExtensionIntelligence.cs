using System.IO;
using System.Text.RegularExpressions;
using DataVanger.Core;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Top-level facade for the Browser Extension Intelligence subsystem.
///
/// Pipeline:
///   1. Detect browser context from the path (BrowserContextDetector).
///   2. Parse manifest.json (ExtensionManifestParser).
///   3. Inspect the surrounding folder for frontend-bundler markers
///      (FrontendBundleDetector).
///   4. Run the trust engine (ExtensionTrustEngine).
///   5. Return an <see cref="AnalysisResult"/> compatible with the
///      legacy detection module contract.
///
/// All evidence emitted here is heuristic — never confirms malware,
/// honouring the project-wide anti-false-positive policy.
/// </summary>
public static class BrowserExtensionIntelligence
{
    /// <summary>
    /// Analyse an extension by manifest.json path. Returns an
    /// <see cref="AnalysisResult"/> with evidence in the "Browser" category.
    /// </summary>
    public static AnalysisResult AnalyzeManifest(string manifestPath, int localSeenCount = 0)
    {
        var result = new AnalysisResult();
        if (string.IsNullOrWhiteSpace(manifestPath)) return result;

        var context = BrowserContextDetector.Detect(manifestPath);
        var manifest = ExtensionManifestParser.Parse(manifestPath);
        string extensionRoot = !string.IsNullOrEmpty(context.ExtensionRoot)
            ? context.ExtensionRoot
            : SafeDirectoryName(manifestPath);
        // If the full browser-profile layout was not detected (e.g. the
        // extension was extracted to a custom location) but the parent
        // directory still matches the Chromium 32-char id shape, treat
        // the id as known so the trust engine can recognise well-known ids.
        if (string.IsNullOrEmpty(context.ExtensionId))
        {
            string maybeId = TryExtractChromiumIdFromPath(extensionRoot);
            if (!string.IsNullOrEmpty(maybeId))
            {
                context = new BrowserContext
                {
                    Browser = context.Browser,
                    IsExtensionContext = context.IsExtensionContext,
                    IsSideLoadedPath = context.IsSideLoadedPath,
                    ProfileRoot = context.ProfileRoot,
                    ExtensionRoot = extensionRoot,
                    ExtensionId = maybeId,
                    ExtensionVersion = context.ExtensionVersion,
                };
            }
        }
        var bundle = FrontendBundleDetector.Inspect(extensionRoot);

        var engine = new ExtensionTrustEngine();
        var evaluation = engine.Evaluate(new ExtensionTrustInput
        {
            Context = context,
            Manifest = manifest,
            Bundle = bundle,
            LocalSeenCount = localSeenCount,
        });

        // Add a header evidence describing browser/extension identity so the
        // UI/report has explainable context regardless of score.
        if (context.IsExtensionContext)
        {
            string head = string.IsNullOrEmpty(manifest.Name)
                ? $"Extensão {context.BrowserName} ({context.ExtensionId})"
                : $"Extensão {context.BrowserName}: {manifest.Name} v{manifest.Version} ({context.ExtensionId})";
            result.Add("Browser", head, 0, EvidenceStrength.Info);
        }
        else if (context.Browser != BrowserKind.Unknown && manifest.ParsedSuccessfully)
        {
            result.Add("Browser",
                $"Manifesto encontrado em perfil de {context.BrowserName}, mas fora de \\Extensions\\",
                0, EvidenceStrength.Info);
        }

        foreach (var ev in evaluation.Evidence) result.Evidence.Add(ev);
        return result;
    }

    private static string SafeDirectoryName(string path)
    {
        try { return Path.GetDirectoryName(path) ?? ""; }
        catch (System.Exception) { return ""; }
    }

    private static readonly Regex ChromiumIdShape = new(
        @"^[a-p]{32}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static string TryExtractChromiumIdFromPath(string extensionRoot)
    {
        if (string.IsNullOrEmpty(extensionRoot)) return "";
        try
        {
            // Layout: ...\<id>\<version>\manifest.json  → extensionRoot is the <version> dir
            // ...so the parent of extensionRoot is the candidate <id> dir.
            var versionDir = new DirectoryInfo(extensionRoot);
            var idDir = versionDir.Parent;
            if (idDir is null) return "";
            return ChromiumIdShape.IsMatch(idDir.Name) ? idDir.Name : "";
        }
        catch (System.Exception)
        {
            return "";
        }
    }
}
