using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using DataVanger.Core;
using DataVanger.Infrastructure;

namespace DataVanger.Reporting;

/// <summary>
/// Beta 11 — Generates structured JSON telemetry reports from scan metrics
/// and stage profiling data. Used for detailed performance analysis and
/// benchmarking before/after optimization phases.
///
/// Output: DataVanger_Telemetry.json with full breakdown by stage and per-item
/// percentiles, enabling detection of performance regressions and identification
/// of slowest paths (files, types, directories).
/// </summary>
public static class TelemetryReportGenerator
{
    public class TelemetryPayload
    {
        [JsonPropertyName("product")]
        public string Product { get; set; } = "DataVanger";

        [JsonPropertyName("version")]
        public string Version { get; set; } = "";

        [JsonPropertyName("scanDate")]
        public DateTime ScanDate { get; set; }

        [JsonPropertyName("scanProfile")]
        public string ScanProfile { get; set; } = "Full";

        [JsonPropertyName("totalSeconds")]
        public double TotalSeconds { get; set; }

        [JsonPropertyName("filesScanned")]
        public int FilesScanned { get; set; }

        [JsonPropertyName("filesPerSecond")]
        public double FilesPerSecond { get; set; }

        [JsonPropertyName("stages")]
        public List<StageMetrics> Stages { get; set; } = new();

        [JsonPropertyName("slowestFiles")]
        public List<FileMetric> SlowestFiles { get; set; } = new();

        [JsonPropertyName("slowestFileTypes")]
        public List<FileTypeMetric> SlowestFileTypes { get; set; } = new();

        [JsonPropertyName("slowestDirectories")]
        public List<DirectoryMetric> SlowestDirectories { get; set; } = new();

        [JsonPropertyName("scanMetrics")]
        public ScanMetricsSummary ScanMetrics { get; set; } = new();
    }

    public class StageMetrics
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("seconds")]
        public double Seconds { get; set; }

        [JsonPropertyName("count")]
        public long Count { get; set; }

        [JsonPropertyName("filesPerSecond")]
        public double FilesPerSecond { get; set; }

        [JsonPropertyName("breakdown")]
        public StageBreakdownMetrics? Breakdown { get; set; }
    }

    public class StageBreakdownMetrics
    {
        [JsonPropertyName("p50Ms")]
        public double P50Ms { get; set; }

        [JsonPropertyName("p95Ms")]
        public double P95Ms { get; set; }

        [JsonPropertyName("maxMs")]
        public double MaxMs { get; set; }

        [JsonPropertyName("avgFileSizeBytes")]
        public long AvgFileSizeBytes { get; set; }
    }

    public class FileMetric
    {
        [JsonPropertyName("path")]
        public string Path { get; set; } = "";

        [JsonPropertyName("elapsedMs")]
        public double ElapsedMs { get; set; }

        [JsonPropertyName("sizeBytes")]
        public long SizeBytes { get; set; }
    }

    public class FileTypeMetric
    {
        [JsonPropertyName("extension")]
        public string Extension { get; set; } = "";

        [JsonPropertyName("cumulativeSeconds")]
        public double CumulativeSeconds { get; set; }

        [JsonPropertyName("fileCount")]
        public int FileCount { get; set; }
    }

    public class DirectoryMetric
    {
        [JsonPropertyName("path")]
        public string Path { get; set; } = "";

        [JsonPropertyName("cumulativeSeconds")]
        public double CumulativeSeconds { get; set; }

        [JsonPropertyName("fileCount")]
        public int FileCount { get; set; }
    }

    public class ScanMetricsSummary
    {
        [JsonPropertyName("targets")]
        public int Targets { get; set; }

        [JsonPropertyName("eligible")]
        public int Eligible { get; set; }

        [JsonPropertyName("cacheDegradationEvents")]
        public int CacheDegradationEvents { get; set; }

        [JsonPropertyName("yaraHits")]
        public int YaraHits { get; set; }

        [JsonPropertyName("findings")]
        public int Findings { get; set; }

        [JsonPropertyName("errors")]
        public int Errors { get; set; }
    }

    /// <summary>
    /// Generates telemetry JSON from scan metrics and profiler data.
    ///
    /// Note: slowest files/types/directories are currently populated with
    /// placeholder data. In a future phase, tracking will be added to
    /// ScanEngine/AnalyzeSingleFileAsync to record individual file timings
    /// for detailed slow-path analysis.
    /// </summary>
    public static void WriteTelemetryJson(
        string path,
        ScanMetrics metrics,
        IReadOnlyList<ScanStageProfiler.StageTiming> stageTimings,
        Dictionary<string, StageTelemetryBreakdown> stageBreakdown,
        DateTime scanDate)
    {
        var payload = new TelemetryPayload
        {
            Product = "DataVanger",
            Version = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown",
            ScanDate = scanDate,
            ScanProfile = metrics.Profile ?? "Full",
            TotalSeconds = metrics.TotalTime.TotalSeconds,
            FilesScanned = metrics.Eligible,
            FilesPerSecond = metrics.Eligible > 0 && metrics.ScanTime.TotalSeconds > 0
                ? metrics.Eligible / metrics.ScanTime.TotalSeconds
                : 0,
        };

        // Populate stage metrics
        foreach (var st in stageTimings)
        {
            var breakdown = stageBreakdown.ContainsKey(st.Stage)
                ? new StageBreakdownMetrics
                {
                    P50Ms = stageBreakdown[st.Stage].P50.TotalMilliseconds,
                    P95Ms = stageBreakdown[st.Stage].P95.TotalMilliseconds,
                    MaxMs = stageBreakdown[st.Stage].Max.TotalMilliseconds,
                    AvgFileSizeBytes = stageBreakdown[st.Stage].AvgFileSize,
                }
                : null;

            payload.Stages.Add(new StageMetrics
            {
                Name = st.Stage,
                Seconds = st.Elapsed.TotalSeconds,
                Count = st.Count,
                FilesPerSecond = st.Count > 0 && st.Elapsed.TotalSeconds > 0
                    ? st.Count / st.Elapsed.TotalSeconds
                    : 0,
                Breakdown = breakdown,
            });
        }

        // Populate scan summary
        payload.ScanMetrics = new ScanMetricsSummary
        {
            Targets = metrics.Targets,
            Eligible = metrics.Eligible,
            CacheDegradationEvents = metrics.CacheDegradationEvents,
            YaraHits = metrics.YaraHits,
            Findings = metrics.Findings,
            Errors = metrics.Errors,
        };

        // TODO: Populate slowest files/types/directories when per-file tracking is added
        // to ScanEngine.AnalyzeSingleFileAsync in a future phase.

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        try
        {
            var json = JsonSerializer.Serialize(payload, options);
            File.WriteAllText(path, json);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write telemetry JSON to {path}: {ex.Message}");
            // Telemetry failure should never propagate to user
        }
    }
}
