using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Core;

public enum ThreatClass
{
    Clean,
    Suspect,
    HighRisk,
    ConfirmedMalware
}

/// <summary>
/// Camada central e auditável de classificação de ameaças.
///
/// Regra de ouro: não acusar sem prova. CRÍTICO/malware confirmado só com
/// evidência forte (hash conhecido em blacklist/base de malware). Heurística
/// forte sem confirmação por hash nunca passa de ALTO RISCO — entra na revisão
/// manual, não em ação automática.
///
/// Nota de arquitetura (fusão v2.0 + v2): a v2.0 tinha uma máquina de estados
/// contextual que decidia a classe a partir de combinações de sinais. Esses
/// critérios (ex.: executável de sistema mascarado fora de System32) foram
/// reaproveitados, mas movidos para a engine como PONTUAÇÃO heurística, não
/// como decisores de classe. Aqui a classificação permanece deliberadamente
/// simples e em um único lugar: a engine pontua, esta camada traduz a
/// pontuação em classe. Detecção rica + classificação auditável.
/// </summary>
public static class ThreatClassificationPolicy
{
    /// <summary>
    /// Determina a classe da ameaça a partir de um achado já pontuado pela engine.
    ///
    /// Malware confirmado:
    ///   - hash SHA256 presente em blacklist/base de malware conhecido; ou
    ///   - regra YARA marcada explicitamente como confirmed=true.
    /// Alto risco heurístico:
    ///   - combinação forte de sinais (score >= High), sem confirmação por hash.
    /// Suspeito/revisão:
    ///   - sinais moderados (score >= Suspect e < High).
    /// Limpo/baixo:
    ///   - sem sinais relevantes (score < Suspect).
    /// </summary>
    public static ThreatClass Classify(ScanFinding finding)
    {
        // ConfirmedMalware (known-malicious hash / confirmed YARA) always wins — the trusted/system
        // gate below can never prevent it.
        if (finding.IsBlacklisted || finding.HasConfirmedSignature) return ThreatClass.ConfirmedMalware;

        if (finding.Score >= RiskThresholds.High)
        {
            // BETA 11E — actionable-corroboration requirement. A trusted-publisher or genuine-system
            // file must not reach ALTO RISCO on summed informational/technical evidence alone; it
            // needs at least one actionable corroborating signal. Numeric thresholds and the Critical
            // clamp are unchanged; this only gates HighRisk -> Suspect (still reported). The gate never
            // applies to unsigned/user-writable/suspicious-path files (TrustedOrSystemContext = false).
            if (finding.TrustedOrSystemContext && !finding.HasActionableCorroboration)
                return ThreatClass.Suspect;
            return ThreatClass.HighRisk;
        }
        if (finding.Score >= RiskThresholds.Suspect) return ThreatClass.Suspect;
        return ThreatClass.Clean;
    }

    /// <summary>
    /// Ação automática só é permitida para malware confirmado por hash.
    /// Todo o resto exige revisão manual antes de quarentenar ou excluir.
    /// </summary>
    public static bool AllowsAutomaticAction(ScanFinding finding) =>
        Classify(finding) == ThreatClass.ConfirmedMalware;

    public static string Label(ThreatClass threatClass) => threatClass switch
    {
        ThreatClass.ConfirmedMalware => "CRÍTICO",
        ThreatClass.HighRisk         => "ALTO RISCO",
        ThreatClass.Suspect          => "SUSPEITO",
        _                            => "LIMPO"
    };

    public static string Color(ThreatClass threatClass) => threatClass switch
    {
        ThreatClass.ConfirmedMalware => "#ff4444",
        ThreatClass.HighRisk         => "#ff8800",
        ThreatClass.Suspect          => "#ffcc00",
        _                            => "#88cc88"
    };

    public static string RecommendedAction(ScanFinding finding)
    {
        if (finding.WasQuarantined) return "Quarentenado";
        return Classify(finding) switch
        {
            ThreatClass.ConfirmedMalware => "Quarentena imediata",
            ThreatClass.HighRisk         => "Revisar manualmente; não quarentenar sem confirmação",
            ThreatClass.Suspect          => "Investigar/monitorar",
            _                            => "Nenhuma ação"
        };
    }

    /// <summary>Ação sugerida na Central de Ações (botão "Revisar e corrigir").</summary>
    public static ReviewAction SuggestedReviewAction(ScanFinding finding) => Classify(finding) switch
    {
        ThreatClass.ConfirmedMalware => ReviewAction.Quarantine,
        ThreatClass.HighRisk         => ReviewAction.Quarantine,
        _                            => ReviewAction.Ignore
    };
}

public enum ReviewAction
{
    Ignore,
    Quarantine,
    Whitelist
}

public static class ReviewActionLabels
{
    public const string Ignore     = "Ignorar";
    public const string Quarantine = "Quarentenar";
    public const string Whitelist  = "Adicionar à whitelist";

    public static readonly IReadOnlyList<string> All = new[] { Ignore, Quarantine, Whitelist };

    public static string ToLabel(ReviewAction action) => action switch
    {
        ReviewAction.Quarantine => Quarantine,
        ReviewAction.Whitelist  => Whitelist,
        _                       => Ignore
    };

    public static ReviewAction FromLabel(string? label) => label switch
    {
        Quarantine => ReviewAction.Quarantine,
        Whitelist  => ReviewAction.Whitelist,
        _          => ReviewAction.Ignore
    };
}
