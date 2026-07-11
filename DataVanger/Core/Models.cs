using System;
using System.Collections.Generic;
using System.IO;
using DataVanger.Reputation;

namespace DataVanger.Core;

public enum ScanProfile { Fast, Deep }

public enum EvidenceStrength
{
    Info,
    Low,
    Medium,
    High,
    Confirmed
}

public sealed class Evidence
{
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public int ScoreDelta { get; set; }
    public EvidenceStrength Strength { get; set; } = EvidenceStrength.Info;
    public bool CanConfirmMalware { get; set; }

    public override string ToString()
    {
        string prefix = string.IsNullOrWhiteSpace(Category) ? "" : $"{Category}: ";
        string score = ScoreDelta == 0 ? "" : $" ({ScoreDelta:+#;-#;0})";
        return $"{prefix}{Description}{score}";
    }
}

public static class RiskThresholds
{
    public const int Suspect  = 6;
    public const int High     = 9;
    public const int Critical = 14;
}

public class ScanFinding
{
    public string Path      { get; set; } = "";
    public string Extension { get; set; } = "";
    public long   SizeKB    { get; set; }
    public string? SHA256   { get; set; }
    public bool   IsSigned  { get; set; }
    public string Publisher { get; set; } = "";
    public int    Score     { get; set; }
    public string Reasons   { get; set; } = "";
    public List<Evidence> Evidence { get; set; } = new();
    public DateTime LastWrite   { get; set; }
    public bool   IsNew         { get; set; }
    public bool   IsBlacklisted { get; set; }
    public bool   HasConfirmedSignature { get; set; }
    public string SignatureName { get; set; } = "";
    public bool   WasQuarantined { get; set; }

    // BETA 11E — trusted/system tier-gate context. Set by the engine; default false keeps the
    // legacy purely-numeric classification for any other ScanFinding source. When the file is in a
    // trusted-publisher/genuine-system context (TrustedOrSystemContext) and has no actionable
    // corroborating signal (HasActionableCorroboration), HighRisk is gated down to Suspect.
    public bool   TrustedOrSystemContext { get; set; }
    public bool   HasActionableCorroboration { get; set; }
    public ReputationTrustState ReputationState { get; set; } = ReputationTrustState.Unknown;
    public int    ReputationScore { get; set; }
    public int    ReputationScoreDelta { get; set; }
    public int    ReputationSeenCount { get; set; }
    public DateTime? ReputationFirstSeenUtc { get; set; }
    public DateTime? ReputationLastSeenUtc { get; set; }
    public string ReputationSignerStatus { get; set; } = "Unknown";
    public string ReputationUserDecision { get; set; } = "None";
    public List<string> ReputationReasons { get; set; } = new();

    public string FileName => string.IsNullOrWhiteSpace(Path) ? "" : System.IO.Path.GetFileName(Path);

    // Classificação delegada à camada central ThreatClassificationPolicy para
    // manter os critérios de detecção auditáveis e em um único lugar.
    public ThreatClass Classification => ThreatClassificationPolicy.Classify(this);

    // CRÍTICO no DataVanger significa confirmação forte, não apenas soma de heurísticas.
    // A quarentena automática continua limitada a hash de malware conhecido.
    public bool IsConfirmedMalware => Classification == ThreatClass.ConfirmedMalware;

    public string RecommendedAction => ThreatClassificationPolicy.RecommendedAction(this);

    public string RiskLabel => ThreatClassificationPolicy.Label(Classification);

    public string RiskColor => ThreatClassificationPolicy.Color(Classification);

    public string EvidenceSummary => Evidence.Count == 0
        ? Reasons
        : string.Join("; ", Evidence.Select(e => e.ToString()));

    public string ReputationSummary => ReputationReasons.Count == 0
        ? $"{ReputationState} ({ReputationScore:+#;-#;0})"
        : $"{ReputationState} ({ReputationScore:+#;-#;0}): {string.Join("; ", ReputationReasons)}";
}

public class ScanOptions
{
    public ScanProfile Profile       { get; set; } = ScanProfile.Deep;
    public long        MaxHashSizeMB { get; set; } = 0;
    public bool        Interactive   { get; set; } = false;
    public int         MaxDegreeOfParallelism { get; set; } = 0;
    public int         CpuThrottleDelayMs { get; set; } = 0;
    public string?     Target { get; set; }
    public string      ReportFormat { get; set; } = "all";
    public bool        ScanArchives { get; set; } = true;
    public bool        ScanBrowserExtensions { get; set; } = true;
    public bool        ScanDocuments { get; set; } = true;
    public int         MaxArchiveDepth { get; set; } = 2;
    public int         MaxArchiveEntries { get; set; } = 600;
    public int         MaxFileSizeMB { get; set; } = 0;
    public bool        AutoQuarantine { get; set; } = true;

    // Optional configuration for Deep profile customization
    public DataVanger.Engine.DeepScanLayerConfig? DeepLayerConfig { get; set; } = null;

    /// <summary>
    /// Opt-in switch for the layered Deep Scan Pipeline introduced in v3.2
    /// (see <c>DataVanger.Engine.DeepScan</c>). When true, Deep/Full profiles
    /// route file analysis through the new staged orchestrator with bounded
    /// parallelism, zip-bomb protection and recursive archive expansion.
    /// </summary>
    public bool        UseDeepScanPipeline { get; set; } = false;

}

public sealed class ScanProgressInfo
{
    public int Current { get; set; }
    public int Total { get; set; }
    public int Remaining => Math.Max(0, Total - Current);
    public double Percent => Total <= 0 ? 0 : Math.Min(100, Current * 100.0 / Total);
    public double FilesPerSecond { get; set; }
    public TimeSpan Eta { get; set; } = TimeSpan.Zero;
    public string CurrentFile { get; set; } = "";
    public string Phase { get; set; } = "";
    public bool IsIndeterminate { get; set; }
}

public class ScanMetrics
{
    public int      Targets                { get; set; }
    public int      Eligible               { get; set; }
    public int      TotalEstimate          { get; set; }
    public int      AccessDenied           { get; set; }
    public int      AnalyzedKnownVendorLocation { get; set; }
    public int      SkippedExcludedPath    { get; set; }
    public int      SkippedKnownSafe       { get; set; }
    public int      SkippedLowScore        { get; set; }
    public int      HashComputed           { get; set; }
    public int      HashSkippedLarge       { get; set; }
    public int      SignatureHashesLoaded  { get; set; }
    public int      YaraRulesLoaded        { get; set; }
    public int      YaraScanned            { get; set; }
    public int      YaraHits               { get; set; }
    public int      ArchiveChecked         { get; set; }
    public int      ArchiveHits            { get; set; }
    public int      DocumentChecked        { get; set; }
    public int      DocumentHits           { get; set; }
    public int      BrowserExtensionChecked { get; set; }
    public int      BrowserExtensionHits    { get; set; }
    public int      KnownMalwareHits       { get; set; }
    public int      AutoQuarantined        { get; set; }
    public int      SigChecked             { get; set; }
    public int      CatalogSignatureHits   { get; set; }
    public int      CacheDegradationEvents { get; set; }
    public int      TrustedWindowsComponentHits { get; set; }
    public int      SystemPathContextApplied { get; set; }
    public int      PeImportsAttenuated    { get; set; }
    public int      EntropyChecked         { get; set; }
    public int      FakeIconChecked        { get; set; }
    public int      AppendChecked          { get; set; }
    public int      AdsChecked             { get; set; }
    public int      ScriptInspected        { get; set; }
    public int      Findings               { get; set; }
    public int      NewFindings            { get; set; }
    public int      RunningProcessHits     { get; set; }
    public int      RunningProcesses       { get; set; }
    public int      PersistenceItems       { get; set; }
    public int      Errors                 { get; set; }
    public TimeSpan ScanTime               { get; set; }
    public TimeSpan TotalTime              { get; set; }

    // Beta 10 — per-stage wall-time profiling (seconds), populated from
    // ScanStageProfiler. Diagnostics/report only; never feeds the classifier.
    public Dictionary<string, double> StageSeconds { get; set; } = new();

    // Beta 11 — per-stage detailed breakdown (percentiles, file size avg), populated from
    // ScanStageProfiler.GetPerItemSnapshot(). Diagnostics/report only.
    public Dictionary<string, StageTelemetryBreakdown> StageBreakdown { get; set; } = new();

    // Beta 11 — scan profile label (e.g. "Full", "Quick") for telemetry export. Nullable so the
    // telemetry generator can fall back to a default when unset; never feeds the classifier.
    public string? Profile { get; set; }

    public double FilesPerSecond => ScanTime.TotalSeconds <= 0 ? 0 : Eligible / ScanTime.TotalSeconds;
}

public class StageTelemetryBreakdown
{
    public TimeSpan Total { get; set; }
    public long Count { get; set; }
    public TimeSpan P50 { get; set; }
    public TimeSpan P95 { get; set; }
    public TimeSpan Max { get; set; }
    public long AvgFileSize { get; set; }

    public double FilesPerSecond => Count > 0 && Total.TotalSeconds > 0 ? Count / Total.TotalSeconds : 0;
}

public sealed class CleanerItem
{
    public string Category { get; set; } = "";
    public string Path { get; set; } = "";
    public long Bytes { get; set; }
    public int FileCount { get; set; }
    public string Risk { get; set; } = "Baixo";
    public string Impact { get; set; } = "Seguro";
    public bool Selected { get; set; } = true;

    // Metadados de medição vindos da JunkCleaningPolicy: permitem ao usuário
    // decidir com mais contexto (idade dos arquivos, presença de arquivos em uso).
    public DateTime? OldestLastWrite { get; set; }
    public DateTime? NewestLastWrite { get; set; }
    public bool HasFilesInUse { get; set; }

    public string SizeLabel => Bytes < 1024 * 1024
        ? $"{Bytes / 1024.0:F1} KB"
        : $"{Bytes / 1024.0 / 1024.0:F1} MB";

    public string LastWriteLabel =>
        NewestLastWrite == null ? "-" : NewestLastWrite.Value.ToString("dd/MM/yyyy HH:mm");
}

public sealed class CleanerResult
{
    public int DeletedFiles { get; set; }
    public long DeletedBytes { get; set; }
    public int SkippedFiles { get; set; }
    public List<string> Messages { get; set; } = new();
}
