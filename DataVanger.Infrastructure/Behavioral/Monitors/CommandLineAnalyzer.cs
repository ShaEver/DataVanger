using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DataVanger.Behavioral.Monitors;

/// <summary>
/// Pure analyzer for process command lines.
///
/// Given a process name and command line, returns a list of behavioral
/// tags (lower-case strings) that other rules can correlate on. The
/// analyzer NEVER decides on its own that something is malware — it
/// only emits descriptive tags.
///
/// Detection categories:
///   - powershell:    EncodedCommand, hidden window, ExecutionPolicy bypass, IEX, DownloadString…
///   - lolbins:       certutil, mshta, rundll32, regsvr32, bitsadmin, msbuild, installutil…
///   - download:      explicit http/https cradles
///   - security:      defender disable, AMSI bypass, ETW tamper, set-mppreference…
///   - persistence:   schtasks /create, reg run keys, new-service…
///   - hidden:        -w hidden, windowstyle hidden…
///   - obfuscation:   long Base64 blobs, char[] arrays, replace/join chains…
/// </summary>
public static class CommandLineAnalyzer
{
    private static readonly HashSet<string> LolbinNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "installutil.exe",
        "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "schtasks.exe",
        "psexec.exe", "psexec64.exe", "msiexec.exe",
    };

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    };

    private static readonly HashSet<string> OfficeProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "visio.exe",
    };

    private static readonly Regex EncodedCommandRx = new(
        @"(?<!\S)(?:-{1,2}|/)(?:e|ec|enc|encodedcommand)\b|frombase64string\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DynamicExecRx = new(
        @"\biex\b|invoke-expression|downloadstring|invoke-webrequest|new-object\s+net\.webclient|start-bitstransfer",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DownloadCradleRx = new(
        @"(http|https)://[^\s'""]+\.(exe|dll|ps1|psm1|bat|cmd|hta|vbs|js|jse|wsf|msi|scr|zip|rar|7z|cab)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HiddenExecutionRx = new(
        @"(?<!\S)(?:-{1,2}|/)(?:w|windowstyle)\s+hidden\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PolicyBypassRx = new(
        @"(?<!\S)(?:-{1,2}|/)(?:ep|executionpolicy)\s+bypass\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SecurityTamperRx = new(
        @"(set-mppreference|disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring|" +
        @"add-mppreference|securityhealthservice|sc\s+(stop|delete|config)\s+windefend|" +
        @"reg\s+add[^|\r\n]+disableantispyware|reg\s+add[^|\r\n]+disablerealtime|" +
        @"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AmsiBypassRx = new(
        @"(amsiscanbuffer|amsiutils|amsiinitfailed|\[ref\]\.assembly\.gettype\(.*system\.management\.automation\.amsi)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PersistenceRx = new(
        @"(schtasks(\.exe)?\s+/create|new-scheduledtask|register-scheduledtask|" +
        @"new-service\b|sc(\.exe)?\s+create\s+|" +
        @"reg\s+add[^|\r\n]+(currentversion\\run|runonce|winlogon))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Conservative obfuscation indicators only. Patterns that occur in
    // normal PS scripts (\${var}, $env:..., single backticks) are explicitly
    // NOT included to keep false positives low.
    private static readonly Regex ObfuscationRx = new(
        @"(\[char\]\d+(\s*,\s*\[char\]\d+){2,}" +
        @"|\.replace\([^)]{0,40}\)\.replace\([^)]{0,40}\)" +
        @"|-join\s*\(\s*\[char\]" +
        @"|[a-z0-9+/]{500,}={0,2})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CredentialAccessRx = new(
        @"(invoke-mimikatz|mimikatz|sekurlsa|lsadump|dumplsa|" +
        @"comsvcs\.dll[^|\r\n]+minidump|" +
        @"\\lsass\.exe|reg\s+save[^|\r\n]+\\sam\b|reg\s+save[^|\r\n]+\\security\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static CommandLineFindings Analyze(string processName, string commandLine)
    {
        var findings = new CommandLineFindings();
        string name = (processName ?? "").Trim().ToLowerInvariant();
        string cmd = commandLine ?? "";

        findings.ProcessName = name;
        findings.IsLolbin = LolbinNames.Contains(name);
        findings.IsScriptHost = ScriptHosts.Contains(name);
        findings.IsOfficeProcess = OfficeProcesses.Contains(name);

        if (string.IsNullOrWhiteSpace(cmd))
        {
            return findings;
        }

        if (EncodedCommandRx.IsMatch(cmd)) findings.Tags.Add("encoded-payload");
        if (DynamicExecRx.IsMatch(cmd)) findings.Tags.Add("dynamic-execution");
        if (DownloadCradleRx.IsMatch(cmd)) findings.Tags.Add("download-cradle");
        if (HiddenExecutionRx.IsMatch(cmd)) findings.Tags.Add("hidden-execution");
        if (PolicyBypassRx.IsMatch(cmd)) findings.Tags.Add("policy-bypass");
        if (SecurityTamperRx.IsMatch(cmd)) findings.Tags.Add("security-tamper");
        if (AmsiBypassRx.IsMatch(cmd)) findings.Tags.Add("amsi-bypass");
        if (PersistenceRx.IsMatch(cmd)) findings.Tags.Add("persistence-action");
        if (ObfuscationRx.IsMatch(cmd)) findings.Tags.Add("obfuscation");
        if (CredentialAccessRx.IsMatch(cmd)) findings.Tags.Add("credential-access");

        return findings;
    }
}

public sealed class CommandLineFindings
{
    public string ProcessName { get; set; } = "";
    public bool IsLolbin { get; set; }
    public bool IsScriptHost { get; set; }
    public bool IsOfficeProcess { get; set; }
    public HashSet<string> Tags { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool HasTag(string tag) => Tags.Contains(tag);
}
