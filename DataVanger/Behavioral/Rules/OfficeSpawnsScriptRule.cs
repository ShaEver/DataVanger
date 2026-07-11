using System;
using System.Collections.Generic;
using DataVanger.Behavioral.Monitors;
using DataVanger.Core;

namespace DataVanger.Behavioral.Rules;

/// <summary>
/// Office application directly spawning a script host or LOLBin.
///
/// This is one of the strongest behavioral indicators (classic phishing
/// macro chain) but still NEVER confirms malware by itself — corporate
/// templates and some add-ins do legitimately spawn scripts.
/// </summary>
public sealed class OfficeSpawnsScriptRule : IBehavioralRule
{
    public string RuleId => "B.OFFICE.SpawnsScript";
    public string Title => "Aplicativo Office originou processo de script/LOLBin";

    public IReadOnlyList<Evidence> Evaluate(BehavioralEvent ev, ProcessAncestry ancestry, BehavioralTimeline timeline)
    {
        if (ev.Kind != BehavioralEventKind.ProcessStart && ev.Kind != BehavioralEventKind.OfficeSpawnsScript)
            return Array.Empty<Evidence>();

        var findings = CommandLineAnalyzer.Analyze(ev.ProcessName, ev.CommandLine);
        if (!(findings.IsScriptHost || findings.IsLolbin)) return Array.Empty<Evidence>();

        string parentName = "";
        if (ev.ParentPid > 0 && ancestry.TryGet(ev.ParentPid, out var parent))
            parentName = parent.ProcessName.ToLowerInvariant();

        bool fromOffice = parentName is "winword.exe" or "excel.exe" or "powerpnt.exe"
            or "outlook.exe" or "msaccess.exe" or "visio.exe";
        if (!fromOffice) return Array.Empty<Evidence>();

        int score = 6;
        if (findings.HasTag("download-cradle")) score += 4;
        if (findings.HasTag("encoded-payload")) score += 3;
        if (findings.HasTag("persistence-action")) score += 4;

        var strength = score >= 9 ? EvidenceStrength.High : EvidenceStrength.Medium;

        return new[]
        {
            new Evidence
            {
                Category = "Behavioral",
                Description = $"{parentName} originou {findings.ProcessName} (cadeia suspeita de macro) pid={ev.Pid}",
                ScoreDelta = score,
                Strength = strength,
                CanConfirmMalware = false,
            }
        };
    }
}
