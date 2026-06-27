using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DataVanger.Engine.Behavioral.Runtime;

/// <summary>
/// Conservative command-line indicator detector for the runtime binding
/// (Phase 2 / Step 06).
///
/// This intentionally mirrors the SPIRIT of the existing main-project
/// CommandLineAnalyzer and of <c>DataVanger.Infrastructure.Etw.
/// EtwPowerShellIndicators</c>, but lives in DataVanger.Engine so the
/// behavioral runtime binding does not take a hard dependency on the
/// main app (WPF) assembly or on the ETW infrastructure assembly. It
/// does NOT rewrite or replace those analyzers — they remain the source
/// of truth for their respective scan/ETW paths.
///
/// Anti-FP guarantee:
///   These indicators are descriptive tags, NOT verdicts. The presence
///   of any tag does not imply ConfirmedMalware.
/// </summary>
public static class BehavioralCommandLineIndicators
{
    // PowerShell command-line tags (kept identical to the ETW tag spellings
    // so evidence is consistent regardless of which path produced it).
    public const string TagPowerShellProcess = "powershell-process";
    public const string TagEncodedCommand    = "powershell-encoded-command";
    public const string TagHiddenWindow      = "powershell-hidden-window";
    public const string TagDynamicExecution  = "powershell-dynamic-execution";
    public const string TagPolicyBypass      = "powershell-policy-bypass";

    // LOLBin argument tag.
    public const string TagLolBinSuspiciousArgs = "lolbin-suspicious-args";

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

    // Suspicious LOLBin argument patterns. Deliberately narrow to avoid
    // flagging benign usage (e.g. plain `certutil -hashfile`).
    private static readonly Regex LolBinSuspiciousRx = new(
        @"-urlcache|-decode|-encode|/transfer\b|http[s]?://|\.hta\b|javascript:|scrobj\.dll|/i:|\bregsvr32\b.*\b/u\b.*\bscrobj|downloadfile|webclient|frombase64string|-windowstyle\s+hidden",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool IsPowerShellProcess(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return false;
        return PowerShellNames.Contains(BehavioralRuntimeProcessCatalog.Normalize(processName));
    }

    /// <summary>
    /// Returns conservative PowerShell indicator tags for a command line.
    /// Always safe to call; never throws.
    /// </summary>
    public static IReadOnlyList<string> DetectPowerShellIndicators(string? processName, string? commandLine)
    {
        var tags = new List<string>(capacity: 4);
        if (!IsPowerShellProcess(processName)) return tags;
        tags.Add(TagPowerShellProcess);

        if (string.IsNullOrEmpty(commandLine)) return tags;
        var cli = commandLine!;
        try
        {
            if (EncodedCommandRx.IsMatch(cli)) tags.Add(TagEncodedCommand);
            if (HiddenWindowRx.IsMatch(cli)) tags.Add(TagHiddenWindow);
            if (DynamicExecRx.IsMatch(cli)) tags.Add(TagDynamicExecution);
            if (PolicyBypassRx.IsMatch(cli)) tags.Add(TagPolicyBypass);
        }
        catch (System.Exception)
        {
            // Never crash the binding on a pathological command line.
        }
        return tags;
    }

    /// <summary>
    /// True when a LOLBin command line carries clearly suspicious
    /// arguments (download/decode/remote-exec patterns). Conservative by
    /// design — benign LOLBin usage returns false.
    /// </summary>
    public static bool HasSuspiciousLolBinArguments(string? commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return false;
        try { return LolBinSuspiciousRx.IsMatch(commandLine!); }
        catch (System.Exception) { return false; }
    }
}
