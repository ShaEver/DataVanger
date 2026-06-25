using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Defensive parser for WebExtension manifest.json files.
///
/// The parser NEVER throws on malformed input — every failure path
/// returns an <see cref="ExtensionManifest"/> with
/// <see cref="ExtensionManifest.ParsedSuccessfully"/> set to <c>false</c>
/// and an explanatory <see cref="ExtensionManifest.ParseError"/>.
///
/// Files larger than <see cref="MaxManifestBytes"/> are rejected as
/// "not a manifest" to avoid loading malicious decoy files.
/// </summary>
public static class ExtensionManifestParser
{
    public const long MaxManifestBytes = 1 * 1024 * 1024;

    public static ExtensionManifest Parse(string manifestPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(manifestPath) || !File.Exists(manifestPath))
                return new ExtensionManifest { ParseError = "manifest not found" };

            var fi = new FileInfo(manifestPath);
            if (fi.Length > MaxManifestBytes)
                return new ExtensionManifest { ParseError = "manifest too large" };

            string json = File.ReadAllText(manifestPath);
            return ParseFromText(json);
        }
        catch (Exception ex)
        {
            return new ExtensionManifest { ParseError = ex.GetType().Name };
        }
    }

    public static ExtensionManifest ParseFromText(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new ExtensionManifest { ParseError = "empty manifest" };

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return new ExtensionManifest { ParseError = "manifest root is not an object" };

            int manifestVersion = ReadInt(root, "manifest_version");
            string name = ReadString(root, "name");
            string version = ReadString(root, "version");
            string description = ReadString(root, "description");
            string updateUrl = ReadString(root, "update_url");
            string author = ReadString(root, "author");
            string homepage = ReadString(root, "homepage_url");

            var permissions = new List<string>();
            var optional = new List<string>();
            var hostPerms = new List<string>();
            ReadStringArray(root, "permissions", permissions);
            ReadStringArray(root, "optional_permissions", optional);
            ReadStringArray(root, "host_permissions", hostPerms);
            ReadStringArray(root, "optional_host_permissions", hostPerms);

            // Manifest V2 mixes host and API permissions in "permissions"
            if (manifestVersion <= 2)
            {
                var migrated = new List<string>();
                foreach (var perm in permissions)
                {
                    if (LooksLikeHostMatch(perm)) hostPerms.Add(perm);
                    else migrated.Add(perm);
                }
                permissions = migrated;
            }

            var (csFiles, csMatches) = ReadContentScripts(root);
            var war = ReadWebAccessibleResources(root);
            var nmHosts = ReadNativeMessagingHosts(root);

            string sw = "";
            var bgScripts = new List<string>();
            string bgPage = "";
            if (root.TryGetProperty("background", out var bg) && bg.ValueKind == JsonValueKind.Object)
            {
                sw = ReadString(bg, "service_worker");
                bgPage = ReadString(bg, "page");
                ReadStringArray(bg, "scripts", bgScripts);
            }

            string csp = ReadCsp(root);
            bool cspUnsafeEval = csp.Contains("unsafe-eval", StringComparison.OrdinalIgnoreCase);
            bool cspRemoteScript = csp.Contains("http://", StringComparison.OrdinalIgnoreCase)
                || csp.Contains("https://", StringComparison.OrdinalIgnoreCase);

            bool externallyConnectable = root.TryGetProperty("externally_connectable", out _);
            bool chromeUrlOverrides = root.TryGetProperty("chrome_url_overrides", out _);
            bool omniboxKeyword = root.TryGetProperty("omnibox", out _);
            bool devToolsPage = root.TryGetProperty("devtools_page", out _);

            bool allowsRemoteCode = cspUnsafeEval
                || cspRemoteScript
                || HasRemoteUrlIn(bgScripts)
                || HasRemoteUrlIn(csFiles);

            return new ExtensionManifest
            {
                ParsedSuccessfully = true,
                ManifestVersion = manifestVersion,
                Name = name,
                Version = version,
                Description = description,
                UpdateUrl = updateUrl,
                Author = author,
                Homepage = homepage,
                Permissions = permissions,
                OptionalPermissions = optional,
                HostPermissions = hostPerms,
                ContentScriptFiles = csFiles,
                ContentScriptMatches = csMatches,
                WebAccessibleResources = war,
                NativeMessagingHosts = nmHosts,
                BackgroundServiceWorker = sw,
                BackgroundScripts = bgScripts,
                BackgroundPage = bgPage,
                AllowsRemoteCode = allowsRemoteCode,
                DeclaresExternallyConnectable = externallyConnectable,
                ContentSecurityPolicy = csp,
                CspAllowsUnsafeEval = cspUnsafeEval,
                CspAllowsRemoteScript = cspRemoteScript,
                DeclaresChromeUrlOverrides = chromeUrlOverrides,
                DeclaresOmniboxKeyword = omniboxKeyword,
                DeclaresDevToolsPage = devToolsPage,
            };
        }
        catch (JsonException ex)
        {
            return new ExtensionManifest { ParseError = "JSON: " + ex.Message };
        }
        catch (Exception ex)
        {
            return new ExtensionManifest { ParseError = ex.GetType().Name };
        }
    }

    private static int ReadInt(JsonElement root, string name)
    {
        if (root.TryGetProperty(name, out var v))
        {
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)) return i;
            if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), out var s)) return s;
        }
        return 0;
    }

    private static string ReadString(JsonElement root, string name)
    {
        if (root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String)
            return v.GetString() ?? "";
        return "";
    }

    private static void ReadStringArray(JsonElement root, string name, List<string> target)
    {
        if (!root.TryGetProperty(name, out var arr) || arr.ValueKind != JsonValueKind.Array) return;
        foreach (var item in arr.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { } s)
                target.Add(s);
    }

    private static (List<string> Files, List<string> Matches) ReadContentScripts(JsonElement root)
    {
        var files = new List<string>();
        var matches = new List<string>();
        if (!root.TryGetProperty("content_scripts", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return (files, matches);

        foreach (var entry in arr.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object) continue;
            ReadStringArray(entry, "js", files);
            ReadStringArray(entry, "css", files);
            ReadStringArray(entry, "matches", matches);
            ReadStringArray(entry, "exclude_matches", matches);
        }
        return (files, matches);
    }

    private static List<string> ReadWebAccessibleResources(JsonElement root)
    {
        var result = new List<string>();
        if (!root.TryGetProperty("web_accessible_resources", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return result;

        foreach (var entry in arr.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.String && entry.GetString() is { } s)
                result.Add(s);
            else if (entry.ValueKind == JsonValueKind.Object)
            {
                ReadStringArray(entry, "resources", result);
                ReadStringArray(entry, "matches", result);
            }
        }
        return result;
    }

    private static List<string> ReadNativeMessagingHosts(JsonElement root)
    {
        var result = new List<string>();
        ReadStringArray(root, "nativeMessagingHosts", result);
        return result;
    }

    private static string ReadCsp(JsonElement root)
    {
        if (!root.TryGetProperty("content_security_policy", out var v)) return "";
        if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? "";
        if (v.ValueKind == JsonValueKind.Object)
        {
            var parts = new List<string>();
            if (v.TryGetProperty("extension_pages", out var ep) && ep.ValueKind == JsonValueKind.String)
                parts.Add(ep.GetString() ?? "");
            if (v.TryGetProperty("sandbox", out var sb) && sb.ValueKind == JsonValueKind.String)
                parts.Add(sb.GetString() ?? "");
            return string.Join(" ; ", parts);
        }
        return "";
    }

    private static bool LooksLikeHostMatch(string permission) =>
        !string.IsNullOrWhiteSpace(permission)
        && (permission.Contains("://") || permission.Equals("<all_urls>", StringComparison.OrdinalIgnoreCase));

    private static bool HasRemoteUrlIn(IEnumerable<string> values)
    {
        foreach (var v in values)
        {
            if (string.IsNullOrWhiteSpace(v)) continue;
            if (v.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || v.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
