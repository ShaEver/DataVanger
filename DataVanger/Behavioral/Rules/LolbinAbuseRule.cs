using System;
using System.Collections.Generic;
using DataVanger.Behavioral.Monitors;
using DataVanger.Core;

namespace DataVanger.Behavioral.Rules;

/// <summary>
/// LOLBin (Living Off The Land binary) abuse: certutil, mshta, rundll32,
/// regsvr32, bitsadmin, msbuild, installutil…
///
/// LOLBin presence alone is benign — they're shipped with Windows. The
/// rule requires that the command line carries a known-abuse pattern
/// (download cradle, encoded payload, persistence action, security
/// tamper) before producing evidence.
/// </summary>
public sealed class LolbinAbuseRule : IBehavioralRule
{
    public string RuleId => "B.LOLBIN.Abuse";
    public string Title => "Uso suspeito de binário Windows (LOLBin)";

    public IReadOnlyList<Evidence> Evaluate(BehavioralEvent ev, ProcessAncestry ancestry, BehavioralTimeline timeline)
    {
        if (ev.Kind != BehavioralEventKind.ProcessStart
            && ev.Kind != BehavioralEventKind.LolbinInvocation)
            return Array.Empty<Evidence>();

        var findings = CommandLineAnalyzer.Analyze(ev.ProcessName, ev.CommandLine);
        if (!findings.IsLolbin) return Array.Empty<Evidence>();

        bool abusive = findings.HasTag("download-cradle")
            || findings.HasTag("encoded-payload")
            || findings.HasTag("persistence-action")
            || findings.HasTag("security-tamper")
            || findings.HasTag("amsi-bypass")
            || findings.HasTag("credential-access");
        if (!abusive) return Array.Empty<Evidence>();

        int score = 3;
        var parts = new List<string> { findings.ProcessName };
        if (findings.HasTag("download-cradle")) { score += 4; parts.Add("download cradle"); }
        if (findings.HasTag("encoded-payload")) { score += 3; parts.Add("payload codificado"); }
        if (findings.HasTag("persistence-action")) { score += 4; parts.Add("persistência"); }
        if (findings.HasTag("security-tamper")) { score += 5; parts.Add("tamper de segurança"); }
        if (findings.HasTag("amsi-bypass")) { score += 6; parts.Add("AMSI bypass"); }
        if (findings.HasTag("credential-access")) { score += 5; parts.Add("acesso a credenciais"); }

        var strength = score >= 8 ? EvidenceStrength.High
            : score >= 5 ? EvidenceStrength.Medium
            : EvidenceStrength.Low;

        return new[]
        {
            new Evidence
            {
                Category = "Behavioral",
                Description = $"LOLBin abusivo: {string.Join(", ", parts)} pid={ev.Pid}",
                ScoreDelta = score,
                Strength = strength,
                CanConfirmMalware = false,
            }
        };
    }
}
