using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Conservative PowerShell command-line indicator detector introduced
/// in Phase 2 Step 05 (ETW Real Provider).
///
/// Returns a small set of indicator tags suitable for placing on a
/// <see cref="DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent"/>
/// metadata bag. The detector intentionally mirrors the spirit of the
/// existing main-project CommandLineAnalyzer but lives in
/// DataVanger.Infrastructure so that the ETW pipeline does not take a
/// hard dependency on the main app.
///
/// Anti-FP guarantee:
///   These indicators are descriptive tags, NOT verdicts. The
///   presence of "powershell-encoded-command" does NOT imply
///   ConfirmedMalware. Verdicts originate from the scan engine and
///   classification policy, not from this detector.
/// </summary>
public static class EtwPowerShellIndicators
{
    public const string TagPowerShellProcess     = "powershell-process";
    public const string TagEncodedCommand        = "powershell-encoded-command";
    public const string TagHiddenWindow          = "powershell-hidden-window";
    public const string TagDynamicExecution      = "powershell-dynamic-execution";
    public const string TagPolicyBypass          = "powershell-policy-bypass";

    private static readonly HashSet<string> PowerShellNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "powershell", "pwsh",
    };

    private static readonly Regex EncodedCommandRx = new(
        @"(?<!\S)(?:-{1,2}|/)(?:e|ec|enc|encodedcommand)\b|frombase64string\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HiddenWindowRx = new(
        @"(?<!\S)(?:-{1,2}|/)(?:w|windowstyle)\s+hidden\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DynamicExecRx = new(
        @"\biex\b|invoke-expression|downloadstring|invoke-webrequest|new-object\s+net\.webclient|start-bitstransfer",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PolicyBypassRx = new(
        @"(?<!\S)(?:-{1,2}|/)(?:ep|executionpolicy)\s+bypass\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Returns true when <paramref name="processName"/> looks like a PowerShell host.</summary>
    public static bool IsPowerShellProcess(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return false;
        var trimmed = processName!.Trim();
        return PowerShellNames.Contains(trimmed);
    }

    /// <summary>
    /// Returns a (possibly empty) list of indicator tags for the supplied
    /// command line. Always safe to call: never throws, returns at most
    /// 5 tags. Tags are stable, lower-case identifiers.
    /// </summary>
    public static IReadOnlyList<string> DetectIndicators(string? processName, string? commandLine)
    {
        var tags = new List<string>(capacity: 4);
        if (!IsPowerShellProcess(processName)) return tags;
        tags.Add(TagPowerShellProcess);

        if (string.IsNullOrEmpty(commandLine)) return tags;
        string cli = commandLine!;

        try
        {
            if (EncodedCommandRx.IsMatch(cli)) tags.Add(TagEncodedCommand);
            if (HiddenWindowRx.IsMatch(cli)) tags.Add(TagHiddenWindow);
            if (DynamicExecRx.IsMatch(cli)) tags.Add(TagDynamicExecution);
            if (PolicyBypassRx.IsMatch(cli)) tags.Add(TagPolicyBypass);
        }
        catch
        {
            // Indicator detector NEVER crashes the provider. Worst case
            // we return only the process tag and move on.
        }

        return tags;
    }
}
