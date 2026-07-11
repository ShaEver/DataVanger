using System;
using System.Collections.Generic;
using DataVanger.Behavioral.Monitors;
using DataVanger.Core;

namespace DataVanger.Behavioral.Rules;

/// <summary>
/// Encoded / hidden PowerShell command lines.
///
/// Moderate signal on its own. Escalates when combined with a download
/// cradle, AMSI-bypass tags or a script-host child of an Office process.
///
/// Never confirms malware. Legitimate IT automation does use encoded
/// commands occasionally, so weights stay conservative.
/// </summary>
public sealed class EncodedPowerShellRule : IBehavioralRule
{
    public string RuleId => "B.PS.Encoded";
    public string Title => "PowerShell com payload codificado ou execução oculta";

    public IReadOnlyList<Evidence> Evaluate(BehavioralEvent ev, ProcessAncestry ancestry, BehavioralTimeline timeline)
    {
        if (ev.Kind != BehavioralEventKind.ProcessStart
            && ev.Kind != BehavioralEventKind.ScriptExecution
            && ev.Kind != BehavioralEventKind.EncodedPayload)
            return Array.Empty<Evidence>();

        var findings = CommandLineAnalyzer.Analyze(ev.ProcessName, ev.CommandLine);
        if (!findings.IsScriptHost) return Array.Empty<Evidence>();

        bool encoded = findings.HasTag("encoded-payload");
        bool hidden = findings.HasTag("hidden-execution");
        bool dynamic = findings.HasTag("dynamic-execution");
        bool download = findings.HasTag("download-cradle");
        bool amsi = findings.HasTag("amsi-bypass");
        bool obf = findings.HasTag("obfuscation");

        if (!(encoded || hidden || dynamic || download || amsi)) return Array.Empty<Evidence>();

        int score = 0;
        var parts = new List<string>();
        if (encoded) { score += 4; parts.Add("EncodedCommand"); }
        if (hidden) { score += 2; parts.Add("execução oculta"); }
        if (dynamic) { score += 3; parts.Add("execução dinâmica"); }
        if (download) { score += 4; parts.Add("download cradle"); }
        if (amsi) { score += 6; parts.Add("AMSI bypass"); }
        if (obf) { score += 2; parts.Add("ofuscação"); }

        // Correlate ancestry: spawned by an Office process bumps severity.
        bool fromOffice = false;
        foreach (var ancestor in ancestry.Ancestors(ev.Pid, maxDepth: 4))
        {
            string an = ancestor.ProcessName.ToLowerInvariant();
            if (an is "winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe")
            {
                fromOffice = true;
                break;
            }
        }
        if (fromOffice) { score += 4; parts.Add($"pai={GetParentName(ev, ancestry)}"); }

        // Strength caps at High — never Confirmed.
        var strength = score >= 8 ? EvidenceStrength.High
            : score >= 4 ? EvidenceStrength.Medium
            : EvidenceStrength.Low;

        return new[]
        {
            new Evidence
            {
                Category = "Behavioral",
                Description = $"PowerShell suspeito ({string.Join(", ", parts)}) pid={ev.Pid}",
                ScoreDelta = score,
                Strength = strength,
                CanConfirmMalware = false,
            }
        };
    }

    private static string GetParentName(BehavioralEvent ev, ProcessAncestry ancestry)
    {
        if (ev.ParentPid <= 0) return "?";
        return ancestry.TryGet(ev.ParentPid, out var p) ? p.ProcessName : ev.ParentPid.ToString();
    }
}
