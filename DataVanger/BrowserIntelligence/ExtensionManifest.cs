using System.Collections.Generic;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Parsed, structured view of a WebExtension manifest.json.
/// All collections are non-null and empty when absent — callers should
/// not need to null-check.
/// </summary>
public sealed class ExtensionManifest
{
    public bool ParsedSuccessfully { get; init; }
    public string ParseError { get; init; } = "";
    public int ManifestVersion { get; init; }
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public string Description { get; init; } = "";
    public string UpdateUrl { get; init; } = "";
    public string Author { get; init; } = "";
    public string Homepage { get; init; } = "";

    public IReadOnlyList<string> Permissions { get; init; } = System.Array.Empty<string>();
    public IReadOnlyList<string> OptionalPermissions { get; init; } = System.Array.Empty<string>();
    public IReadOnlyList<string> HostPermissions { get; init; } = System.Array.Empty<string>();
    public IReadOnlyList<string> ContentScriptFiles { get; init; } = System.Array.Empty<string>();
    public IReadOnlyList<string> ContentScriptMatches { get; init; } = System.Array.Empty<string>();
    public IReadOnlyList<string> WebAccessibleResources { get; init; } = System.Array.Empty<string>();
    public IReadOnlyList<string> NativeMessagingHosts { get; init; } = System.Array.Empty<string>();

    public string BackgroundServiceWorker { get; init; } = "";
    public IReadOnlyList<string> BackgroundScripts { get; init; } = System.Array.Empty<string>();
    public string BackgroundPage { get; init; } = "";

    public bool AllowsRemoteCode { get; init; }
    public bool DeclaresExternallyConnectable { get; init; }
    public string ContentSecurityPolicy { get; init; } = "";
    public bool CspAllowsUnsafeEval { get; init; }
    public bool CspAllowsRemoteScript { get; init; }

    public bool DeclaresChromeUrlOverrides { get; init; }
    public bool DeclaresOmniboxKeyword { get; init; }
    public bool DeclaresDevToolsPage { get; init; }

    public bool HasAnyContent => Permissions.Count > 0 || HostPermissions.Count > 0 || ManifestVersion > 0;
}
