using System.IO;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Read-only snapshot of the browser-extension context discovered for a
/// given file path. Built by <see cref="BrowserContextDetector"/> and
/// consumed by the trust engine and the manifest analyzer.
///
/// IsExtensionContext is the gate: when false the analyzer must NOT emit
/// the "browser-aware downgrade" because the file is not actually living
/// inside a browser profile.
/// </summary>
public sealed class BrowserContext
{
    public static BrowserContext None { get; } = new()
    {
        Browser = BrowserKind.Unknown,
        IsExtensionContext = false,
        IsSideLoadedPath = false,
        ProfileRoot = "",
        ExtensionRoot = "",
        ExtensionId = "",
        ExtensionVersion = "",
    };

    public required BrowserKind Browser { get; init; }
    public required bool IsExtensionContext { get; init; }

    /// <summary>True for unpacked / developer-mode / sideloaded installs.</summary>
    public required bool IsSideLoadedPath { get; init; }

    public required string ProfileRoot { get; init; }
    public required string ExtensionRoot { get; init; }
    public required string ExtensionId { get; init; }
    public required string ExtensionVersion { get; init; }

    public string BrowserName => Browser switch
    {
        BrowserKind.Chrome   => "Google Chrome",
        BrowserKind.Edge     => "Microsoft Edge",
        BrowserKind.Brave    => "Brave",
        BrowserKind.Opera    => "Opera",
        BrowserKind.Vivaldi  => "Vivaldi",
        BrowserKind.Chromium => "Chromium",
        BrowserKind.Helium   => "Helium",
        BrowserKind.Firefox  => "Mozilla Firefox",
        _ => "",
    };

    /// <summary>Best-effort guess at the manifest path inside the extension root.</summary>
    public string ManifestPath => string.IsNullOrEmpty(ExtensionRoot)
        ? ""
        : Path.Combine(ExtensionRoot, "manifest.json");
}
