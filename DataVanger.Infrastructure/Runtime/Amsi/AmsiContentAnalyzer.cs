using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Pure analyzer for AMSI script content.
///
/// Builds on top of <see cref="DataVanger.Behavioral.Monitors.CommandLineAnalyzer"/>
/// (so tag taxonomy stays consistent) and layers a few content-specific
/// checks that don't make sense on raw command lines (long Base64 blobs
/// inside script bodies, reflective .NET loaders, etc.).
///
/// The analyzer is intentionally conservative — it only tags content,
/// never makes a malware verdict. Tags feed the bridge which converts
/// them into <see cref="DataVanger.Behavioral.BehavioralEvent"/>s.
/// </summary>
public static class AmsiContentAnalyzer
{
    // Reflective .NET loading inside a script. Very strong signal when
    // combined with downloader / FromBase64String / Invoke.
    private static readonly Regex ReflectiveLoadRx = new(
        @"\[reflection\.assembly\]::load\s*\(|" +
        @"\[system\.reflection\.assembly\]::load\s*\(|" +
        @"\.assembly\.gettype\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // FromBase64String + IEX/Invoke style payload assembly.
    private static readonly Regex Base64InvokeRx = new(
        @"\[(?:system\.)?convert\]::frombase64string\s*\([^)]{16,}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Long Base64 blob embedded in script body (separate from the command-
    // line obfuscation rule which already covers >=500 chars).
    private static readonly Regex LongBase64Rx = new(
        @"[A-Za-z0-9+/]{256,}={0,2}",
        RegexOptions.Compiled);

    // Defender / AV tamper inside script body (subset of CommandLineAnalyzer's
    // pattern, but specifically for script content where the keyword may
    // appear in different surrounding context).
    private static readonly Regex DefenderTamperRx = new(
        @"set-mppreference\b|disablerealtimemonitoring\b|disableantispyware\b|" +
        @"add-mppreference\b|stop-service\s+windefend",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static AmsiContentFindings Analyze(string source, string scriptContent)
    {
        var f = new AmsiContentFindings { Source = source ?? "" };
        if (string.IsNullOrWhiteSpace(scriptContent)) return f;

        // Reuse the behavioral command-line tags so downstream rules
        // already understand them.
        var clTags = DataVanger.Behavioral.Monitors.CommandLineAnalyzer
            .Analyze(source ?? "amsi", scriptContent);
        foreach (var tag in clTags.Tags) f.Tags.Add(tag);

        if (ReflectiveLoadRx.IsMatch(scriptContent)) f.Tags.Add("reflective-load");
        if (Base64InvokeRx.IsMatch(scriptContent))   f.Tags.Add("base64-invoke");
        if (LongBase64Rx.IsMatch(scriptContent))     f.Tags.Add("long-base64");
        if (DefenderTamperRx.IsMatch(scriptContent)) f.Tags.Add("security-tamper");

        return f;
    }
}

public sealed class AmsiContentFindings
{
    public string Source { get; set; } = "";
    public HashSet<string> Tags { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool HasTag(string tag) => Tags.Contains(tag);
}
