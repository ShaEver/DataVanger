using System;
using System.Collections.Generic;

namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Permission risk catalog for Chromium / Firefox WebExtensions.
///
/// Each permission falls into one of three buckets:
///   - High risk     : strongly correlated with credential theft, hijacking
///                     or native abuse. Worth raising on its own combined
///                     with other signals — never confirms malware.
///   - Moderate risk : useful to attackers but also widely used by legitimate
///                     extensions (debuggers, dev tools, password managers).
///   - Low risk      : informational only.
///
/// Anything not listed here is treated as <see cref="PermissionRiskLevel.Low"/>.
/// </summary>
public static class ExtensionPermissionCatalog
{
    private static readonly Dictionary<string, PermissionRiskLevel> _table = new(StringComparer.OrdinalIgnoreCase)
    {
        // High risk
        ["nativeMessaging"]     = PermissionRiskLevel.High,
        ["debugger"]            = PermissionRiskLevel.High,
        ["management"]          = PermissionRiskLevel.High,
        ["proxy"]               = PermissionRiskLevel.High,
        ["privacy"]             = PermissionRiskLevel.High,
        ["downloads.open"]      = PermissionRiskLevel.High,

        // Moderate risk (broad, but legitimately common)
        ["webRequest"]          = PermissionRiskLevel.Moderate,
        ["webRequestBlocking"]  = PermissionRiskLevel.Moderate,
        ["cookies"]             = PermissionRiskLevel.Moderate,
        ["history"]             = PermissionRiskLevel.Moderate,
        ["tabs"]                = PermissionRiskLevel.Moderate,
        ["scripting"]           = PermissionRiskLevel.Moderate,
        ["activeTab"]           = PermissionRiskLevel.Moderate,
        ["downloads"]           = PermissionRiskLevel.Moderate,
        ["clipboardRead"]       = PermissionRiskLevel.Moderate,
        ["clipboardWrite"]      = PermissionRiskLevel.Moderate,
        ["<all_urls>"]          = PermissionRiskLevel.Moderate,
        ["storage"]             = PermissionRiskLevel.Low,
        ["notifications"]       = PermissionRiskLevel.Low,
        ["alarms"]              = PermissionRiskLevel.Low,
        ["contextMenus"]        = PermissionRiskLevel.Low,
        ["identity"]            = PermissionRiskLevel.Moderate,
        ["bookmarks"]           = PermissionRiskLevel.Moderate,
        ["geolocation"]         = PermissionRiskLevel.Moderate,
    };

    public static PermissionRiskLevel Classify(string permission)
    {
        if (string.IsNullOrWhiteSpace(permission)) return PermissionRiskLevel.Low;
        // Host permissions: schemes like "https://*/*" and "<all_urls>"
        if (permission.Contains("://") && (permission.Contains("/*") || permission.Contains("<all_urls>")))
        {
            // A wildcard scheme matching every host is broad enough to be Moderate.
            return permission.StartsWith("*://*/", StringComparison.OrdinalIgnoreCase)
                || permission.StartsWith("http://*/", StringComparison.OrdinalIgnoreCase)
                || permission.StartsWith("https://*/", StringComparison.OrdinalIgnoreCase)
                || permission.Equals("<all_urls>", StringComparison.OrdinalIgnoreCase)
                ? PermissionRiskLevel.Moderate
                : PermissionRiskLevel.Low;
        }
        return _table.TryGetValue(permission, out var level) ? level : PermissionRiskLevel.Low;
    }
}

public enum PermissionRiskLevel
{
    Low = 0,
    Moderate = 1,
    High = 2,
}
