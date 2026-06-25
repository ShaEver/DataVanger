using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Settings;

/// <summary>
/// The single, behaviour-preserving description of DataVanger's settings for the
/// redesigned UI. It groups the existing <see cref="AppSettings"/> fields, marks
/// reveal tier and risk, and flags protection toggles for confirm-on-disable. It
/// stores no values and changes no defaults or thresholds.
/// </summary>
public static class SettingsCatalog
{
    /// <summary>Editable boolean settings, with typed accessors onto AppSettings.</summary>
    public static IReadOnlyList<ToggleSetting> Toggles { get; } = BuildToggles();

    /// <summary>Non-boolean settings (numbers/text/list) described for grouping and
    /// reveal-gating. The redesigned window keeps raw foot-gun values in
    /// Advanced/Developer; their editors remain in the legacy advanced window.</summary>
    public static IReadOnlyList<SettingMetadata> MetadataOnly { get; } = BuildMetadataOnly();

    /// <summary>All settings metadata (toggles + non-toggles).</summary>
    public static IReadOnlyList<SettingMetadata> AllMetadata { get; } =
        Toggles.Select(t => t.Meta).Concat(MetadataOnly).ToArray();

    private static IReadOnlyList<ToggleSetting> BuildToggles() => new List<ToggleSetting>
    {
        // ── Real-time protection ───────────────────────────────────────────
        Toggle("EnableTrayProtection", "Proteção residente (bandeja)",
            "Mantém o monitor em tempo real ativo na bandeja. Desativar deixa o sistema sem proteção contínua.",
            SettingGroup.RealTimeProtection, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.EnableTrayProtection, (s, v) => s.EnableTrayProtection = v),

        // ── Threat removal ─────────────────────────────────────────────────
        Toggle("AutoQuarantineKnownMalware", "Quarentena automática de malware conhecido",
            "Coloca em quarentena automaticamente apenas malware confirmado por hash conhecido. Desativar reduz a proteção.",
            SettingGroup.ThreatRemoval, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.AutoQuarantineKnownMalware, (s, v) => s.AutoQuarantineKnownMalware = v),

        // ── Scanning (Normal) ──────────────────────────────────────────────
        Toggle("EnableYaraRules", "Regras YARA",
            "Usa regras YARA leves locais para reforçar a detecção. Desativar reduz a cobertura.",
            SettingGroup.Scanning, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.EnableYaraRules, (s, v) => s.EnableYaraRules = v),
        Toggle("ScanStartupLocations", "Verificar locais de inicialização",
            "Inclui pontos de autoexecução do Windows na varredura. Desativar reduz a detecção de persistência.",
            SettingGroup.Scanning, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.ScanStartupLocations, (s, v) => s.ScanStartupLocations = v),
        Toggle("ScanDownloads", "Verificar Downloads",
            "Inclui a pasta Downloads na varredura.",
            SettingGroup.Scanning, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.ScanDownloads, (s, v) => s.ScanDownloads = v),
        Toggle("ScanDesktop", "Verificar Área de Trabalho",
            "Inclui a Área de Trabalho na varredura.",
            SettingGroup.Scanning, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.ScanDesktop, (s, v) => s.ScanDesktop = v),
        Toggle("ScanDocuments", "Verificar Documentos",
            "Inclui a pasta Documentos na varredura.",
            SettingGroup.Scanning, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.ScanDocuments, (s, v) => s.ScanDocuments = v),
        Toggle("ScanAppData", "Verificar AppData",
            "Inclui a pasta AppData na varredura, onde malware costuma se instalar.",
            SettingGroup.Scanning, SettingVisibility.Normal, SettingRisk.Protection, confirmOnDisable: true,
            s => s.ScanAppData, (s, v) => s.ScanAppData = v),

        // ── Scanning (Advanced detection depth) ────────────────────────────
        Toggle("DeepScanArchives", "Varredura profunda de compactados",
            "Analisa o conteúdo de arquivos ZIP/JAR/Office. Desativar reduz a detecção em compactados.",
            SettingGroup.Scanning, SettingVisibility.Advanced, SettingRisk.Protection, confirmOnDisable: true,
            s => s.DeepScanArchives, (s, v) => s.DeepScanArchives = v),
        Toggle("AnalyzeDocuments", "Analisar documentos Office",
            "Inspeciona documentos Office em busca de macros/relações externas.",
            SettingGroup.Scanning, SettingVisibility.Advanced, SettingRisk.Protection, confirmOnDisable: true,
            s => s.AnalyzeDocuments, (s, v) => s.AnalyzeDocuments = v),
        Toggle("AnalyzeBrowserExtensions", "Analisar extensões de navegador",
            "Inspeciona extensões de navegador instaladas.",
            SettingGroup.Scanning, SettingVisibility.Advanced, SettingRisk.Protection, confirmOnDisable: true,
            s => s.AnalyzeBrowserExtensions, (s, v) => s.AnalyzeBrowserExtensions = v),
        Toggle("IncludeRemovableDrives", "Incluir unidades removíveis",
            "Inclui pen drives e unidades removíveis na varredura. Desligado por padrão.",
            SettingGroup.Scanning, SettingVisibility.Advanced, SettingRisk.Caution, confirmOnDisable: false,
            s => s.IncludeRemovableDrives, (s, v) => s.IncludeRemovableDrives = v),

        // ── Advanced diagnostics (detection depth) ─────────────────────────
        Toggle("AnalyzeAlternateDataStreams", "Analisar fluxos de dados alternativos (ADS)",
            "Inspeciona ADS NTFS, usados para ocultar conteúdo.",
            SettingGroup.AdvancedDiagnostics, SettingVisibility.Advanced, SettingRisk.Protection, confirmOnDisable: true,
            s => s.AnalyzeAlternateDataStreams, (s, v) => s.AnalyzeAlternateDataStreams = v),
        Toggle("AdvancedPersistenceChecks", "Checagens avançadas de persistência",
            "Verifica mais pontos de persistência do Windows. Desativar reduz a detecção.",
            SettingGroup.AdvancedDiagnostics, SettingVisibility.Advanced, SettingRisk.Protection, confirmOnDisable: true,
            s => s.AdvancedPersistenceChecks, (s, v) => s.AdvancedPersistenceChecks = v),
        Toggle("AnalyzeServicesAndDrivers", "Analisar serviços e drivers",
            "Inspeciona serviços e drivers em busca de comprometimento.",
            SettingGroup.AdvancedDiagnostics, SettingVisibility.Advanced, SettingRisk.Protection, confirmOnDisable: true,
            s => s.AnalyzeServicesAndDrivers, (s, v) => s.AnalyzeServicesAndDrivers = v),
        Toggle("AnalyzeScheduledTasks", "Analisar tarefas agendadas",
            "Inspeciona tarefas agendadas, um vetor comum de persistência.",
            SettingGroup.AdvancedDiagnostics, SettingVisibility.Advanced, SettingRisk.Protection, confirmOnDisable: true,
            s => s.AnalyzeScheduledTasks, (s, v) => s.AnalyzeScheduledTasks = v),
        Toggle("UseSafeCache", "Usar cache seguro",
            "Acelera varreduras repetidas reutilizando resultados confiáveis. Ajuste de desempenho.",
            SettingGroup.AdvancedDiagnostics, SettingVisibility.Advanced, SettingRisk.Safe, confirmOnDisable: false,
            s => s.UseSafeCache, (s, v) => s.UseSafeCache = v),

        // ── Privacy ────────────────────────────────────────────────────────
        Toggle("SuppressAccessDeniedLog", "Ocultar avisos de acesso negado no log",
            "Reduz o ruído no log ocultando avisos de acesso negado. Apenas cosmético.",
            SettingGroup.Privacy, SettingVisibility.Advanced, SettingRisk.Safe, confirmOnDisable: false,
            s => s.SuppressAccessDeniedLog, (s, v) => s.SuppressAccessDeniedLog = v),

        // ── Updates (opt-in) ───────────────────────────────────────────────
        Toggle("EnableHttpSignedUpdates", "Atualizações assinadas via HTTP (opt-in)",
            "Habilita o transporte HTTP opt-in para atualizações assinadas. Desligado por padrão.",
            SettingGroup.Updates, SettingVisibility.Developer, SettingRisk.Caution, confirmOnDisable: false,
            s => s.EnableHttpSignedUpdates, (s, v) => s.EnableHttpSignedUpdates = v),
    };

    private static IReadOnlyList<SettingMetadata> BuildMetadataOnly() => new List<SettingMetadata>
    {
        Meta("ExtraTrustedPublishers", "Editores confiáveis adicionais",
            "Lista aditiva de editores confiáveis além da base curada. Não remove a lista base.",
            SettingGroup.General, SettingKind.List, SettingVisibility.Advanced, SettingRisk.Caution, "list"),
        Meta("SignatureUpdateUrl", "URL de atualização de assinaturas",
            "Origem opcional para atualização da base de assinaturas.",
            SettingGroup.Updates, SettingKind.Text, SettingVisibility.Advanced, SettingRisk.Caution, "url"),
        Meta("YaraMaxScanSizeMB", "Tamanho máximo para YARA (MB)",
            "Limite de tamanho de arquivo analisado por regras YARA.",
            SettingGroup.Scanning, SettingKind.Number, SettingVisibility.Advanced, SettingRisk.Caution, "MB"),
        Meta("ArchiveMaxEntries", "Máximo de entradas por compactado",
            "Limite de entradas inspecionadas por arquivo compactado.",
            SettingGroup.Scanning, SettingKind.Number, SettingVisibility.Advanced, SettingRisk.Caution, "count"),
        Meta("ArchiveMaxDepth", "Profundidade máxima de compactados",
            "Quantos níveis de compactados aninhados inspecionar.",
            SettingGroup.Scanning, SettingKind.Number, SettingVisibility.Advanced, SettingRisk.Caution, "count"),
        Meta("ArchiveMaxDecompressedMB", "Limite descompactado (MB)",
            "Tamanho máximo descompactado inspecionado por compactado.",
            SettingGroup.Scanning, SettingKind.Number, SettingVisibility.Advanced, SettingRisk.Caution, "MB"),
        // Raw danger thresholds — foot-guns; hidden from Normal users.
        Meta("MinScoreToReport", "Pontuação mínima para relatar (avançado)",
            "Valor bruto de detecção. Alterar afeta sensibilidade; manter conservador.",
            SettingGroup.DeveloperExperimental, SettingKind.Number, SettingVisibility.Developer, SettingRisk.Caution, "score"),
        Meta("MinScoreToQuarantine", "Pontuação mínima para quarentena (avançado)",
            "Valor bruto de detecção. Alterar afeta quando itens entram em quarentena; manter conservador.",
            SettingGroup.DeveloperExperimental, SettingKind.Number, SettingVisibility.Developer, SettingRisk.Caution, "score"),
        Meta("PublisherValidationMode", "Modo de validação de editor (avançado)",
            "Modo de confiança de assinatura. O padrão preserva o comportamento legado.",
            SettingGroup.DeveloperExperimental, SettingKind.Text, SettingVisibility.Developer, SettingRisk.Caution, "mode"),
    };

    private static ToggleSetting Toggle(
        string key, string name, string description,
        SettingGroup group, SettingVisibility visibility, SettingRisk risk, bool confirmOnDisable,
        System.Func<AppSettings, bool> getter, System.Action<AppSettings, bool> setter)
        => new(
            new SettingMetadata
            {
                Key = key,
                DisplayName = name,
                Description = description,
                Group = group,
                Kind = SettingKind.Toggle,
                Visibility = visibility,
                Risk = risk,
                ConfirmOnDisable = confirmOnDisable,
                Dimension = "boolean",
            },
            getter, setter);

    private static SettingMetadata Meta(
        string key, string name, string description,
        SettingGroup group, SettingKind kind, SettingVisibility visibility, SettingRisk risk, string dimension)
        => new()
        {
            Key = key,
            DisplayName = name,
            Description = description,
            Group = group,
            Kind = kind,
            Visibility = visibility,
            Risk = risk,
            ConfirmOnDisable = false,
            Dimension = dimension,
        };
}
