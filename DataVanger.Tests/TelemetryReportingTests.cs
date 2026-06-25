using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using DataVanger.Core;
using DataVanger.Infrastructure;
using DataVanger.Reporting;

using Xunit;

namespace DataVanger.Tests;

/// <summary>
/// Phase 11 telemetry and profiling tests.
/// Verify that stage instrumentation, per-item metrics, and JSON export work correctly.
/// </summary>
public class TelemetryReportingTests
{
    [Fact]
    public void ScanStageProfiler_RecordsBasicStageMetrics()
    {
        var profiler = new ScanStageProfiler();

        using (profiler.Measure("TestStage1"))
            System.Threading.Thread.Sleep(10);

        using (profiler.Measure("TestStage2"))
            System.Threading.Thread.Sleep(5);

        var snapshot = profiler.Snapshot();

        Assert.NotEmpty(snapshot);
        Assert.Contains(snapshot, s => s.Stage == "TestStage1");
        Assert.Contains(snapshot, s => s.Stage == "TestStage2");
        Assert.True(snapshot[0].Elapsed > TimeSpan.Zero);
    }

    [Fact]
    public void ScanStageProfiler_PerItemMetrics_TracksDistribution()
    {
        var profiler = new ScanStageProfiler();

        // Simulate 10 files being processed in "Hashing" stage
        for (int i = 0; i < 10; i++)
        {
            long ticks = (long)System.Diagnostics.Stopwatch.Frequency * (i + 1);  // 1s, 2s, 3s, ...
            profiler.RecordItemMetrics("Hashing", ticks, fileSize: 1000 * (i + 1));
        }

        var snapshot = profiler.GetPerItemSnapshot("Hashing");
        Assert.NotNull(snapshot);
        Assert.Equal(10, snapshot.Value.Count);
        Assert.True(snapshot.Value.P50 > TimeSpan.Zero);
        Assert.True(snapshot.Value.P95 >= snapshot.Value.P50);
        Assert.True(snapshot.Value.Max >= snapshot.Value.P95);
    }

    [Fact]
    public void ScanStageProfiler_PerItemMetrics_CalculatesPercentiles()
    {
        var profiler = new ScanStageProfiler();

        // Add 5 items with increasing durations
        for (int i = 1; i <= 5; i++)
        {
            long ticks = (long)System.Diagnostics.Stopwatch.Frequency * i;
            profiler.RecordItemMetrics("Analysis", ticks, 100 * i);
        }

        var snapshot = profiler.GetPerItemSnapshot("Analysis");
        Assert.NotNull(snapshot);

        // With 5 items, P50 should be around item 3 (60% percentile roughly)
        // P95 should be around item 5 (max)
        Assert.True(snapshot.Value.P50.TotalSeconds >= 2 && snapshot.Value.P50.TotalSeconds <= 4);
        Assert.True(snapshot.Value.P95.TotalSeconds >= 4);
        Assert.Equal(5, snapshot.Value.Count);
    }

    [Fact]
    public void ScanStageProfiler_NonExistentStage_ReturnsNull()
    {
        var profiler = new ScanStageProfiler();
        var snapshot = profiler.GetPerItemSnapshot("NonExistent");
        Assert.Null(snapshot);
    }

    [Fact]
    public void StageTelemetryBreakdown_ComputesFilesPerSecond()
    {
        var breakdown = new StageTelemetryBreakdown
        {
            Total = TimeSpan.FromSeconds(10),
            Count = 100,
            P50 = TimeSpan.FromMilliseconds(50),
            P95 = TimeSpan.FromMilliseconds(150),
            Max = TimeSpan.FromMilliseconds(500),
            AvgFileSize = 1000,
        };

        Assert.Equal(10.0, breakdown.FilesPerSecond);
    }

    [Fact]
    public void TelemetryReportGenerator_WritesValidJson()
    {
        var metrics = new ScanMetrics
        {
            Eligible = 100,
            Targets = 5,
            HashCacheHits = 20,
            YaraHits = 3,
            Findings = 2,
            Errors = 0,
            ScanTime = TimeSpan.FromSeconds(15),
            TotalTime = TimeSpan.FromSeconds(20),
            Profile = "Full",
        };

        var stageTimings = new List<ScanStageProfiler.StageTiming>
        {
            new("Hashing", TimeSpan.FromSeconds(10), 100),
            new("Detection", TimeSpan.FromSeconds(5), 100),
        };

        var stageBreakdown = new Dictionary<string, StageTelemetryBreakdown>
        {
            ["Hashing"] = new()
            {
                Total = TimeSpan.FromSeconds(10),
                Count = 100,
                P50 = TimeSpan.FromMilliseconds(50),
                P95 = TimeSpan.FromMilliseconds(150),
                Max = TimeSpan.FromMilliseconds(500),
                AvgFileSize = 2000,
            },
            ["Detection"] = new()
            {
                Total = TimeSpan.FromSeconds(5),
                Count = 100,
                P50 = TimeSpan.FromMilliseconds(25),
                P95 = TimeSpan.FromMilliseconds(75),
                Max = TimeSpan.FromMilliseconds(250),
                AvgFileSize = 2000,
            },
        };

        var tempPath = Path.Combine(Path.GetTempPath(), "test_telemetry.json");
        try
        {
            TelemetryReportGenerator.WriteTelemetryJson(
                tempPath, metrics, stageTimings, stageBreakdown, DateTime.UtcNow);

            Assert.True(File.Exists(tempPath), "Telemetry JSON file must be created");

            var json = File.ReadAllText(tempPath);
            Assert.Contains("\"stages\"", json);
            Assert.Contains("\"Hashing\"", json);
            Assert.Contains("\"p95Ms\"", json);

            // Validate JSON structure
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("product", out var product));
            Assert.Equal("DataVanger", product.GetString());
            Assert.True(root.TryGetProperty("stages", out var stages));
            Assert.Equal(2, stages.GetArrayLength());
        }
        finally
        {
            if (File.Exists(tempPath))
                File.Delete(tempPath);
        }
    }

    [Fact]
    public void ScanMetrics_StageBreakdown_InitializesAsEmpty()
    {
        var metrics = new ScanMetrics();
        Assert.NotNull(metrics.StageBreakdown);
        Assert.Empty(metrics.StageBreakdown);
    }

    [Fact]
    public void AppSettings_EnableDetailedTelemetry_DefaultIsFalse()
    {
        var settings = new AppSettings();
        Assert.False(settings.EnableDetailedTelemetry);
    }

    [Fact]
    public void AppSettings_EnableDetailedTelemetry_CanBeSet()
    {
        var settings = new AppSettings { EnableDetailedTelemetry = true };
        Assert.True(settings.EnableDetailedTelemetry);
    }
}
