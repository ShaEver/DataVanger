using System;
using System.Text.RegularExpressions;
using DataVanger.Core;

namespace DataVanger.Detection;

/// <summary>
/// Centralised path-classification predicates.
///
/// Originally embedded as private statics inside <c>ScanEngine</c>. Lifting
/// them into a dedicated, public static class lets every detection module
/// reuse the same risk/context vocabulary without re-deriving it. Vendor
/// locations are context only and never establish safety or scan eligibility.
///
/// All inputs are expected to be lower-cased already.
/// </summary>
public static class PathTaxonomy
{
    private static readonly string _tpWindir = P(Environment.SpecialFolder.Windows);
    private static readonly string _tpLocal = P(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string _tpCommon = P(Environment.SpecialFolder.CommonApplicationData);
    private static readonly string _tpProgramFiles = P(Environment.SpecialFolder.ProgramFiles);
    private static readonly string _tpProgramFilesX86 = P(Environment.SpecialFolder.ProgramFilesX86);

    private static string P(Environment.SpecialFolder f)
    {
        var p = Environment.GetFolderPath(f).ToLowerInvariant();
        return string.IsNullOrWhiteSpace(p) ? "" : p.TrimEnd('\\') + "\\";
    }

    private static bool HasPrefix(string fullLower, string prefix) =>
        !string.IsNullOrWhiteSpace(prefix) && prefix != "\\" && fullLower.StartsWith(prefix);

    public static bool IsKnownVendorLocation(string fullLower) =>
        HasPrefix(fullLower, _tpWindir + "winsxs\\")
        || HasPrefix(fullLower, _tpWindir + "servicing\\")
        || HasPrefix(fullLower, _tpCommon + "microsoft\\")
        || HasPrefix(fullLower, _tpLocal + "microsoft\\")
        || HasPrefix(fullLower, _tpLocal + "google\\")
        || HasPrefix(fullLower, _tpLocal + "bravesoftware\\")
        || HasPrefix(fullLower, _tpLocal + "discord\\")
        || HasPrefix(fullLower, _tpLocal + "spotify\\")
        || HasPrefix(fullLower, _tpLocal + "steam\\");

    public static bool IsProtectedWindowsPath(string fullLower) =>
        HasPrefix(fullLower, _tpWindir + "system32\\")
        || HasPrefix(fullLower, _tpWindir + "syswow64\\")
        || HasPrefix(fullLower, _tpWindir + "winsxs\\")
        || HasPrefix(fullLower, _tpWindir + "servicing\\");

    // ── BETA 11B — explicit, canonical system-path classification ──
    // Classifies a file by its genuine Windows location, resolved against the REAL
    // %WinDir% (not a substring), so look-alikes such as C:\Temp\System32 or
    // C:\Users\me\Downloads\System32 are rejected (return None). The windir-relative
    // overload is exposed for OS-independent unit tests; production uses the resolved
    // _tpWindir. This is context only — it never proves safety on its own.

    public static SystemPathKind ClassifySystemPath(string fullLower) =>
        ClassifySystemPath(fullLower, _tpWindir);

    internal static SystemPathKind ClassifySystemPath(string fullLower, string windirPrefixLower)
    {
        if (string.IsNullOrWhiteSpace(fullLower) || string.IsNullOrWhiteSpace(windirPrefixLower))
            return SystemPathKind.None;

        string w = windirPrefixLower.EndsWith("\\") ? windirPrefixLower : windirPrefixLower + "\\";

        // Well-known WORLD-WRITABLE locations inside %WinDir% must never receive
        // protected-system relief (they are classic non-admin write / UAC-bypass dirs).
        if (HasPrefix(fullLower, w + "temp\\")
            || HasPrefix(fullLower, w + "tasks\\")
            || HasPrefix(fullLower, w + "tracing\\")
            || HasPrefix(fullLower, w + "debug\\")
            || HasPrefix(fullLower, w + "system32\\tasks\\")
            || HasPrefix(fullLower, w + "system32\\spool\\")
            || HasPrefix(fullLower, w + "syswow64\\tasks\\"))
            return SystemPathKind.None;

        if (HasPrefix(fullLower, w + "system32\\")) return SystemPathKind.System32;
        if (HasPrefix(fullLower, w + "syswow64\\")) return SystemPathKind.SysWOW64;
        if (HasPrefix(fullLower, w + "winsxs\\"))   return SystemPathKind.WinSxS;
        if (HasPrefix(fullLower, w + "servicing\\")) return SystemPathKind.Servicing;
        // Other genuine Windows component locations (Temp/Tasks/etc. already excluded above).
        if (HasPrefix(fullLower, w))
            return SystemPathKind.OtherProtectedWindows;
        return SystemPathKind.None;
    }

    /// <summary>
    /// Bounded heuristic-noise relief for a genuine protected Windows location. Always
    /// small (≤ 4) so it can attenuate noise but can NEVER grant immunity: a strongly
    /// corroborated file stays above the HighRisk threshold. <see cref="SystemPathKind.None"/>
    /// (incl. all user-writable/look-alike paths) receives zero relief.
    /// </summary>
    public static int SystemPathRelief(SystemPathKind kind) => kind switch
    {
        SystemPathKind.System32 or SystemPathKind.SysWOW64
            or SystemPathKind.WinSxS or SystemPathKind.Servicing => 4,
        SystemPathKind.OtherProtectedWindows => 2,
        _ => 0,
    };

    public static bool IsMicrosoftProductPath(string fullLower) =>
        fullLower.Contains("\\microsoft\\")
        || fullLower.Contains("\\microsoft office\\")
        || fullLower.Contains("\\microsoft vs code\\")
        || fullLower.Contains("\\onedrive\\")
        || fullLower.Contains("\\edge\\user data\\");

    public static bool IsUserWritableRiskPath(string fullLower) =>
        fullLower.Contains("\\temp\\")
        || fullLower.Contains("\\downloads\\")
        || fullLower.Contains("\\desktop\\")
        || fullLower.Contains("\\appdata\\")
        || fullLower.Contains("\\$recycle.bin\\");

    public static bool IsTempRandomScript(string fullLower, string name, string ext) =>
        (ext is ".js" or ".jse" or ".vbs" or ".wsf" or ".ps1" or ".hta")
        && fullLower.Contains("\\temp\\")
        && Regex.IsMatch(name, @"^[{(]?[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}[)}]?\.tmp\.");

    /// <summary>
    /// True when a critical system-process executable sits in its genuine canonical
    /// home. The masquerading heuristic must NOT fire there: <c>explorer.exe</c>
    /// legitimately lives in the Windows root (and SysWOW64), not System32, so the
    /// real shell was being false-flagged. Every other critical name lives under
    /// System32/SysWOW64. Resolved against the REAL %WinDir% (exact path match),
    /// so a look-alike such as C:\Temp\explorer.exe returns false (still flagged).
    /// </summary>
    public static bool IsSystemExeInCanonicalHome(string fullLower, string nameLower)
        => IsSystemExeInCanonicalHome(fullLower, nameLower, _tpWindir);

    // The windir-relative overload is exposed for OS-independent unit tests (the real
    // %WinDir% is empty off-Windows); production uses the resolved _tpWindir.
    internal static bool IsSystemExeInCanonicalHome(string fullLower, string nameLower, string windirPrefixLower)
    {
        if (string.IsNullOrEmpty(fullLower) || string.IsNullOrEmpty(nameLower) || string.IsNullOrEmpty(windirPrefixLower))
            return false;
        string w = windirPrefixLower.EndsWith("\\") ? windirPrefixLower : windirPrefixLower + "\\";

        if (nameLower == "explorer.exe")
            return fullLower == w + "explorer.exe"
                || fullLower == w + "syswow64\\explorer.exe";

        return fullLower == w + "system32\\" + nameLower
            || fullLower == w + "syswow64\\" + nameLower;
    }
}

/// <summary>
/// BETA 11B — explicit Windows system-path taxonomy. Used as scoring CONTEXT only
/// (bounded relief), never as proof of safety, an allowlist, or an indexing skip.
/// </summary>
public enum SystemPathKind
{
    None = 0,
    System32,
    SysWOW64,
    WinSxS,
    Servicing,
    OtherProtectedWindows,
}
