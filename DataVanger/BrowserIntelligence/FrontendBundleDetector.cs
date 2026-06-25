using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Recognises common frontend-bundler output (webpack / vite / rollup /
/// parcel / esbuild / React / Vue / Angular). When the extension folder
/// contains clear signs of a legitimate frontend build, the trust engine
/// strongly suppresses static-only escalation.
///
/// Detection is intentionally lightweight: directory listing + a tiny
/// peek into a couple of JS files. No AST, no deobfuscation.
///
/// This is the heart of the anti-false-positive strategy described in
/// the spec: "Modern browser extensions frequently resemble malware
/// statically. minified JS, Base64, packed bundles are NORMAL."
/// </summary>
public static class FrontendBundleDetector
{
    private const int MaxFilesToScan = 12;
    private const int MaxBytesPerFile = 8 * 1024;

    private static readonly string[] BundlerMarkers =
    {
        "webpackJsonp",
        "__webpack_require__",
        "webpack/runtime",
        "webpack_chunk",
        "__webpack_modules__",
        "__esModule",
        "import.meta.url",
        "vite/preload",
        "__vite__",
        "createElement",            // React
        "useState",                 // React
        "react-dom",
        "Vue.prototype",
        "@vue/runtime",
        "Vue.createApp",
        "platformBrowserDynamic",   // Angular
        "ɵngcc",                    // Angular Ivy NGCC marker
        "rollup",
        "esbuild",
        "parcelRequire",
    };

    private static readonly Regex ChunkFilePattern = new(
        @"^(chunk[-.]|runtime[-.]|main[-.]|vendor[-.]|polyfill|[0-9a-f]{8,}\.)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static FrontendBundleProfile Inspect(string extensionRoot)
    {
        var profile = new FrontendBundleProfile();
        if (string.IsNullOrWhiteSpace(extensionRoot) || !Directory.Exists(extensionRoot))
            return profile;

        try
        {
            string[] files = SafeListFiles(extensionRoot);
            profile.JavaScriptFileCount = CountWithExtension(files, ".js");
            profile.CssFileCount = CountWithExtension(files, ".css");
            profile.WasmFileCount = CountWithExtension(files, ".wasm");
            profile.MapFileCount = CountWithExtension(files, ".map");
            profile.HasLocalesFolder = Directory.Exists(Path.Combine(extensionRoot, "_locales"));
            profile.HasMetadataFolder = Directory.Exists(Path.Combine(extensionRoot, "_metadata"));
            profile.HasIconsFolder = Directory.Exists(Path.Combine(extensionRoot, "icons"))
                                  || Directory.Exists(Path.Combine(extensionRoot, "img"))
                                  || Directory.Exists(Path.Combine(extensionRoot, "images"));

            int chunkLooking = 0;
            int scanned = 0;
            var markersFound = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var file in files)
            {
                if (scanned >= MaxFilesToScan) break;
                string name = Path.GetFileName(file);
                if (ChunkFilePattern.IsMatch(name)) chunkLooking++;

                if (!name.EndsWith(".js", StringComparison.OrdinalIgnoreCase)) continue;
                string head = PeekHead(file, MaxBytesPerFile);
                if (string.IsNullOrEmpty(head)) continue;
                scanned++;

                foreach (var marker in BundlerMarkers)
                {
                    if (head.Contains(marker, StringComparison.Ordinal))
                        markersFound.Add(marker);
                }
            }

            profile.ChunkFileNameCount = chunkLooking;
            profile.MarkersFound = markersFound;
            profile.IsRecognisedBundle = markersFound.Count > 0 || chunkLooking >= 2;
        }
        catch
        {
            // Best-effort — never throw out of detection.
        }

        return profile;
    }

    private static string[] SafeListFiles(string root)
    {
        try
        {
            return Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static int CountWithExtension(string[] files, string extension)
    {
        int count = 0;
        foreach (var f in files)
            if (f.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) count++;
        return count;
    }

    private static string PeekHead(string path, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, useAsync: false);
            int length = (int)Math.Min(fs.Length, maxBytes);
            if (length <= 0) return "";
            var buf = new byte[length];
            int read = fs.Read(buf, 0, length);
            return System.Text.Encoding.UTF8.GetString(buf, 0, read);
        }
        catch
        {
            return "";
        }
    }
}

public sealed class FrontendBundleProfile
{
    public bool IsRecognisedBundle { get; set; }
    public int JavaScriptFileCount { get; set; }
    public int CssFileCount { get; set; }
    public int WasmFileCount { get; set; }
    public int MapFileCount { get; set; }
    public int ChunkFileNameCount { get; set; }
    public bool HasLocalesFolder { get; set; }
    public bool HasMetadataFolder { get; set; }
    public bool HasIconsFolder { get; set; }
    public HashSet<string> MarkersFound { get; set; } = new(System.StringComparer.OrdinalIgnoreCase);

    /// <summary>True when several signals point to a legitimate, well-structured extension package.</summary>
    public bool LooksLegitimatelyPackaged => HasLocalesFolder || HasMetadataFolder || HasIconsFolder
                                             || ChunkFileNameCount >= 2
                                             || (IsRecognisedBundle && MarkersFound.Count >= 2);
}
