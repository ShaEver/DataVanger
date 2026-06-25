using System;
using System.Collections.Generic;

namespace DataVanger.Engine.Behavioral.Runtime;

/// <summary>
/// Small, conservative catalogs of well-known process names and risky
/// path fragments used by the runtime behavior rules (Phase 2 / Step 06).
///
/// These are descriptive reference sets, NOT block lists. Membership in a
/// set never confirms malware; it only provides context for conservative,
/// non-confirming behavioral evidence.
/// </summary>
public static class BehavioralRuntimeProcessCatalog
{
    /// <summary>Known Microsoft Office host processes.</summary>
    public static readonly IReadOnlySet<string> OfficeProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
    };

    /// <summary>Script interpreters / shells commonly abused as Office children.</summary>
    public static readonly IReadOnlySet<string> ScriptInterpreters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe",
    };

    /// <summary>Living-off-the-land binaries that warrant context-sensitive scrutiny.</summary>
    public static readonly IReadOnlySet<string> LolBins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "wmic.exe", "schtasks.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
    };

    /// <summary>User-writable path fragments that are higher risk for executable launch.</summary>
    private static readonly string[] RiskyPathFragments =
    {
        @"\temp\", @"\tmp\",
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\appdata\local\",
        @"\downloads\",
        @"\microsoft\windows\inetcache\",
        @"\inetcache\",
        @"\temporary internet files\",
    };

    /// <summary>Environment-style tokens that also denote risky locations.</summary>
    private static readonly string[] RiskyEnvTokens =
    {
        "%temp%", "%tmp%", "%appdata%", "%localappdata%",
    };

    public static bool IsOfficeProcess(string? name) => name is not null && OfficeProcesses.Contains(Normalize(name));

    public static bool IsScriptInterpreter(string? name) => name is not null && ScriptInterpreters.Contains(Normalize(name));

    public static bool IsLolBin(string? name) => name is not null && LolBins.Contains(Normalize(name));

    /// <summary>
    /// True when the supplied image path lives in a user-writable risky
    /// location. Conservative: returns false for null/empty input and for
    /// ordinary system locations.
    /// </summary>
    public static bool IsRiskyExecutablePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return false;
        var lowered = imagePath!.Replace('/', '\\').ToLowerInvariant();

        foreach (var token in RiskyEnvTokens)
        {
            if (lowered.Contains(token, StringComparison.Ordinal)) return true;
        }
        foreach (var fragment in RiskyPathFragments)
        {
            if (lowered.Contains(fragment, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    /// <summary>
    /// Reduce a process name or full image path to a comparable executable
    /// file name (lower-case, last path segment). Never throws.
    /// </summary>
    public static string Normalize(string? nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return string.Empty;
        var s = nameOrPath!.Trim().Replace('/', '\\');
        var idx = s.LastIndexOf('\\');
        if (idx >= 0 && idx < s.Length - 1) s = s.Substring(idx + 1);
        return s.Trim();
    }
}
