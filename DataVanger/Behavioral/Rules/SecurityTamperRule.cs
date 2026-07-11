using System;
using System.Collections.Generic;
using DataVanger.Behavioral.Monitors;
using DataVanger.Core;

namespace DataVanger.Behavioral.Rules;

/// <summary>
/// Active attempts to disable Defender, AMSI, the firewall or other
/// security infrastructure.
///
/// High signal but still heuristic — never confirms malware. The
/// emitted evidence is HighRisk-tier strength so the classifier can
/// promote a correlated finding to HighRisk on its own, but it remains
/// short of <see cref="EvidenceStrength.Confirmed"/>.
/// </summary>
public sealed class SecurityTamperRule : IBehavioralRule
{
    public string RuleId => "B.SEC.Tamper";
    public string Title => "Tentativa de alterar/desligar mecanismo de segurança";

    public IReadOnlyList<Evidence> Evaluate(BehavioralEvent ev, ProcessAncestry ancestry, BehavioralTimeline timeline)
    {
        if (ev.Kind != BehavioralEventKind.ProcessStart
            && ev.Kind != BehavioralEventKind.SecurityTamperIndicator
            && ev.Kind != BehavioralEventKind.AmsiBypassIndicator)
            return Array.Empty<Evidence>();

        var findings = CommandLineAnalyzer.Analyze(ev.ProcessName, ev.CommandLine);
        bool tamper = findings.HasTag("security-tamper");
        bool amsi = findings.HasTag("amsi-bypass");
        if (!tamper && !amsi && ev.Kind != BehavioralEventKind.SecurityTamperIndicator) return Array.Empty<Evidence>();

        int score = 0;
        var parts = new List<string>();
        if (tamper) { score += 6; parts.Add("desabilitar antivírus/firewall"); }
        if (amsi)   { score += 6; parts.Add("AMSI bypass"); }
        if (ev.Kind == BehavioralEventKind.SecurityTamperIndicator && parts.Count == 0)
        {
            score += 5;
            parts.Add(string.IsNullOrEmpty(ev.ExtraTag) ? "indicador" : ev.ExtraTag);
        }

        return new[]
        {
            new Evidence
            {
                Category = "Behavioral",
                Description = $"Tamper de segurança: {string.Join(", ", parts)} (proc={ev.ProcessName} pid={ev.Pid})",
                ScoreDelta = score,
                Strength = EvidenceStrength.High,
                CanConfirmMalware = false,
            }
        };
    }
}
