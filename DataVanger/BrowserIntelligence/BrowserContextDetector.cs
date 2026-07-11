using System;
using System.IO;
using System.Text.RegularExpressions;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Recognises whether a file path is inside a known browser-extension
/// directory layout. Path-only: no IO, no parsing — safe to call for
/// every file in the scan.
///
/// Layouts modelled:
///   Chromium family (Chrome/Edge/Brave/Opera/Vivaldi/Chromium/Helium):
///     ...\&lt;Browser&gt;\User Data\&lt;Profile&gt;\Extensions\&lt;id&gt;\&lt;version&gt;\manifest.json
///   Firefox:
///     ...\Mozilla\Firefox\Profiles\&lt;profile&gt;\extensions\&lt;id&gt;.xpi
///
/// Anything that does not clearly match one of these layouts is reported
/// as <see cref="BrowserContext.None"/>. This is intentional: assuming a
/// browser context outside a real profile would weaken the anti-FP
/// downgrade for unrelated AppData JS files.
/// </summary>
public static class BrowserContextDetector
{
    // <id>/<version> segment shape: 32 lowercase letters then a SemVer-ish version dir
    private static readonly Regex ChromiumExtensionIdAndVersion = new(
        @"\\extensions\\(?<id>[a-p]{32})\\(?<version>[^\\]+)(\\|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FirefoxExtensionId = new(
        @"\\mozilla\\firefox\\profiles\\[^\\]+\\extensions\\(?<id>[^\\]+)(\\|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static BrowserContext Detect(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return BrowserContext.None;
        string normalized = fullPath.Replace('/', '\\');
        string lower = normalized.ToLowerInvariant();

        var browser = DetectBrowser(lower);
        if (browser == BrowserKind.Firefox) return DetectFirefox(normalized, lower);
        if (browser != BrowserKind.Unknown) return DetectChromium(browser, normalized, lower);

        return BrowserContext.None;
    }

    /// <summary>True when the path is rooted inside any recognised browser profile, even outside Extensions.</summary>
    public static bool IsKnownBrowserProfilePath(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return false;
        string lower = fullPath.Replace('/', '\\').ToLowerInvariant();
        return DetectBrowser(lower) != BrowserKind.Unknown;
    }

    private static BrowserKind DetectBrowser(string lower)
    {
        if (lower.Contains("\\google\\chrome\\user data\\")) return BrowserKind.Chrome;
        if (lower.Contains("\\microsoft\\edge\\user data\\")) return BrowserKind.Edge;
        if (lower.Contains("\\bravesoftware\\brave-browser\\user data\\")) return BrowserKind.Brave;
        if (lower.Contains("\\opera software\\opera stable\\")) return BrowserKind.Opera;
        if (lower.Contains("\\vivaldi\\user data\\")) return BrowserKind.Vivaldi;
        if (lower.Contains("\\chromium\\user data\\")) return BrowserKind.Chromium;
        if (lower.Contains("\\helium\\user data\\")) return BrowserKind.Helium;
        if (lower.Contains("\\mozilla\\firefox\\")) return BrowserKind.Firefox;
        return BrowserKind.Unknown;
    }

    private static BrowserContext DetectChromium(BrowserKind browser, string fullPath, string lower)
    {
        var match = ChromiumExtensionIdAndVersion.Match(fullPath);
        if (!match.Success)
        {
            // The path is in a known browser profile but not inside an /Extensions/<id>/<version>/ tree.
            // We still report the browser but mark IsExtensionContext = false so the trust engine
            // doesn't downgrade unrelated files (e.g. cache).
            return new BrowserContext
            {
                Browser = browser,
                IsExtensionContext = false,
                IsSideLoadedPath = false,
                ProfileRoot = ExtractProfileRoot(fullPath, browser),
                ExtensionRoot = "",
                ExtensionId = "",
                ExtensionVersion = "",
            };
        }

        string extensionId = match.Groups["id"].Value;
        string version = match.Groups["version"].Value;
        // ExtensionRoot is the version directory.
        int afterVersion = match.Index + match.Length;
        string extensionRoot = fullPath.Substring(0, afterVersion).TrimEnd('\\');
        bool sideLoaded = lower.Contains("\\external_extensions\\") || lower.Contains("\\developer\\");

        return new BrowserContext
        {
            Browser = browser,
            IsExtensionContext = true,
            IsSideLoadedPath = sideLoaded,
            ProfileRoot = ExtractProfileRoot(fullPath, browser),
            ExtensionRoot = extensionRoot,
            ExtensionId = extensionId,
            ExtensionVersion = version,
        };
    }

    private static BrowserContext DetectFirefox(string fullPath, string lower)
    {
        var match = FirefoxExtensionId.Match(fullPath);
        if (!match.Success)
        {
            return new BrowserContext
            {
                Browser = BrowserKind.Firefox,
                IsExtensionContext = false,
                IsSideLoadedPath = false,
                ProfileRoot = ExtractProfileRoot(fullPath, BrowserKind.Firefox),
                ExtensionRoot = "",
                ExtensionId = "",
                ExtensionVersion = "",
            };
        }

        string id = match.Groups["id"].Value;
        string root = fullPath.Substring(0, match.Index + match.Length).TrimEnd('\\');
        // Firefox extensions are typically xpi (a zip) — we still expose the id.
        return new BrowserContext
        {
            Browser = BrowserKind.Firefox,
            IsExtensionContext = true,
            IsSideLoadedPath = false,
            ProfileRoot = ExtractProfileRoot(fullPath, BrowserKind.Firefox),
            ExtensionRoot = root,
            ExtensionId = id,
            ExtensionVersion = "",
        };
    }

    private static string ExtractProfileRoot(string fullPath, BrowserKind browser)
    {
        try
        {
            string anchor = browser switch
            {
                BrowserKind.Chrome   => "\\Google\\Chrome\\User Data\\",
                BrowserKind.Edge     => "\\Microsoft\\Edge\\User Data\\",
                BrowserKind.Brave    => "\\BraveSoftware\\Brave-Browser\\User Data\\",
                BrowserKind.Opera    => "\\Opera Software\\Opera Stable\\",
                BrowserKind.Vivaldi  => "\\Vivaldi\\User Data\\",
                BrowserKind.Chromium => "\\Chromium\\User Data\\",
                BrowserKind.Helium   => "\\Helium\\User Data\\",
                BrowserKind.Firefox  => "\\Mozilla\\Firefox\\",
                _ => "",
            };
            if (string.IsNullOrEmpty(anchor)) return "";
            int idx = fullPath.IndexOf(anchor, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";
            int end = idx + anchor.Length;
            // Profile name is the next directory after the anchor.
            int next = fullPath.IndexOf('\\', end);
            return next < 0 ? fullPath.Substring(0, end).TrimEnd('\\') : fullPath.Substring(0, next);
        }
        catch (System.Exception)
        {
            return "";
        }
    }
}
