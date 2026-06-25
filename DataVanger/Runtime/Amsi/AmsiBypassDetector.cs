using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Heuristic detector for AMSI bypass indicators in script content.
///
/// Real bypass attempts target <c>amsi.dll!AmsiScanBuffer</c> or
/// <c>System.Management.Automation.AmsiUtils.amsiInitFailed</c>. The
/// detector looks for these textual signatures plus a few well-known
/// patches/variants. It only emits a tag — the bridge decides what to
/// do with it.
///
/// As with every other piece of the runtime telemetry pipeline, an
/// AMSI bypass tag is NOT a malware confirmation. It is one strong
/// signal that the correlation engine can combine with others (encoded
/// payload, suspicious parent process, persistence creation, ...).
/// </summary>
public static class AmsiBypassDetector
{
    private static readonly Regex AmsiUtilsRx = new(
        @"system\.management\.automation\.amsiutils",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AmsiInitFailedRx = new(
        @"amsiinitfailed",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AmsiScanBufferRx = new(
        @"amsiscanbuffer",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AmsiContextRx = new(
        @"amsicontext|amsi_result_clean|amsi\.dll",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex GetFieldNonPublicRx = new(
        @"getfield\s*\(\s*['""](?:amsiinitfailed|amsicontext|amsisession)['""].{0,80}nonpublic",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Returns a list of bypass-indicator reasons. Empty list = no bypass detected.</summary>
    public static IReadOnlyList<string> Detect(string scriptContent)
    {
        if (string.IsNullOrWhiteSpace(scriptContent)) return Array.Empty<string>();
        var reasons = new List<string>();
        if (GetFieldNonPublicRx.IsMatch(scriptContent))
            reasons.Add("reflexão para campos privados de AmsiUtils");
        if (AmsiUtilsRx.IsMatch(scriptContent))
            reasons.Add("referência direta a System.Management.Automation.AmsiUtils");
        if (AmsiInitFailedRx.IsMatch(scriptContent))
            reasons.Add("tentativa de marcar amsiInitFailed = true");
        if (AmsiScanBufferRx.IsMatch(scriptContent))
            reasons.Add("manipulação direta de AmsiScanBuffer");
        if (AmsiContextRx.IsMatch(scriptContent))
            reasons.Add("manipulação de contexto AMSI");
        return reasons;
    }

    public static bool IsLikelyBypass(string scriptContent) => Detect(scriptContent).Count > 0;
}
