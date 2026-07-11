using System;
using DataVanger.Core;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Typed, profile-derived knobs for the Deep Scan Pipeline.
///
/// Everything that varies with <see cref="ScanProfile"/> lives here, so a new
/// profile (or a future "DeepPlus") can be added in one place without grepping
/// the pipeline for magic numbers. The settings combine a hard-coded profile
/// baseline with whatever the user provided in <see cref="AppSettings"/> and
/// <see cref="ScanOptions"/> — user values are clamped, never blindly trusted.
/// </summary>
public sealed class DeepScanProfileSettings
{
    public ScanProfile Profile { get; init; } = ScanProfile.Deep;

    // ---- Recursion / archive limits -----------------------------------------

    /// <summary>Maximum recursive depth when walking nested archives. 0 = no expansion.</summary>
    public int MaxArchiveDepth { get; init; }

    /// <summary>Maximum number of entries inspected per archive container.</summary>
    public int MaxArchiveEntries { get; init; }

    /// <summary>Maximum cumulative decompressed size, in bytes, allowed for one root archive tree.</summary>
    public long MaxTotalDecompressedBytes { get; init; }

    /// <summary>Maximum compression ratio (decompressed/compressed) for a single entry before it is treated as a bomb.</summary>
    public int MaxCompressionRatio { get; init; }

    /// <summary>Hard upper bound on the number of nested archives one root archive may spawn.</summary>
    public int MaxNestedArchives { get; init; }

    // ---- File / content limits ----------------------------------------------

    /// <summary>Maximum file size, in bytes, fully scanned (hash + content modules). 0 = unlimited.</summary>
    public long MaxFileBytes { get; init; }

    /// <summary>Maximum size, in bytes, of an in-archive entry that is streamed into memory for content analysis.</summary>
    public long MaxInMemoryEntryBytes { get; init; }

    // ---- Concurrency / responsiveness ---------------------------------------

    /// <summary>Maximum number of concurrent file workers driving the pipeline.</summary>
    public int MaxDegreeOfParallelism { get; init; }

    /// <summary>Optional CPU throttle delay, milliseconds, inserted between work items.</summary>
    public int CpuThrottleDelayMs { get; init; }

    /// <summary>Capacity of the bounded work-item channel; bounds queue backlog and memory.</summary>
    public int WorkQueueCapacity { get; init; }

    /// <summary>
    /// Hard upper bound on the number of findings retained per scan. Acts as a defensive
    /// resource cap so a pathological input (giant archive full of suspicious files,
    /// runaway detection module) cannot grow <see cref="DeepScanContext.Findings"/>
    /// without bound. 0 = unlimited (legacy behavior). Excess findings are dropped
    /// silently after the cap is reached; the result still surfaces normally via
    /// telemetry counters.
    /// </summary>
    public int MaxFindings { get; init; }

    // ---- Timeouts -----------------------------------------------------------

    /// <summary>Maximum wall-clock time spent analyzing a single file (all stages combined).</summary>
    public TimeSpan PerFileTimeout { get; init; }

    /// <summary>Maximum time spent decompressing / walking one archive entry.</summary>
    public TimeSpan PerArchiveTimeout { get; init; }

    /// <summary>Maximum time spent hashing a single stream.</summary>
    public TimeSpan PerHashTimeout { get; init; }

    /// <summary>Maximum time the whole scan may run; <see cref="TimeSpan.Zero"/> = no overall cap.</summary>
    public TimeSpan OverallTimeout { get; init; }

    // ---- Feature toggles ----------------------------------------------------

    public bool InspectArchives { get; init; }
    public bool InspectDocuments { get; init; }
    public bool InspectBrowserExtensions { get; init; }
    public bool InspectAlternateDataStreams { get; init; }
    public bool ResolveRealFileType { get; init; }
    public bool CorrelateEvidence { get; init; }
    public bool EmitStageTelemetry { get; init; }

    /// <summary>
    /// Builds the canonical profile settings for the supplied profile, blending
    /// in user-provided overrides while clamping them to safe ranges.
    /// </summary>
    public static DeepScanProfileSettings Resolve(ScanProfile profile, AppSettings settings, ScanOptions options)
    {
        settings ??= new AppSettings();
        options  ??= new ScanOptions { Profile = profile };

        int defaultDop = Math.Clamp(Environment.ProcessorCount / 2, 2, 8);
        int dop = options.MaxDegreeOfParallelism > 0
            ? Math.Clamp(options.MaxDegreeOfParallelism, 1, Math.Max(1, Environment.ProcessorCount * 2))
            : defaultDop;

        return profile switch
        {
            ScanProfile.Fast => new DeepScanProfileSettings
            {
                Profile = profile,
                MaxArchiveDepth = 0,
                MaxArchiveEntries = 0,
                MaxTotalDecompressedBytes = 0,
                MaxCompressionRatio = 100,
                MaxNestedArchives = 0,
                MaxFileBytes = Mb(options.MaxFileSizeMB > 0 ? options.MaxFileSizeMB : 64),
                MaxInMemoryEntryBytes = Mb(8),
                MaxDegreeOfParallelism = Math.Min(dop, 4),
                CpuThrottleDelayMs = options.CpuThrottleDelayMs,
                WorkQueueCapacity = 1024,
                MaxFindings = 50_000,
                PerFileTimeout = TimeSpan.FromSeconds(15),
                PerArchiveTimeout = TimeSpan.FromSeconds(5),
                PerHashTimeout = TimeSpan.FromSeconds(10),
                OverallTimeout = TimeSpan.FromMinutes(10),
                InspectArchives = false,
                InspectDocuments = false,
                InspectBrowserExtensions = false,
                InspectAlternateDataStreams = false,
                ResolveRealFileType = false,
                CorrelateEvidence = true,
                EmitStageTelemetry = false,
            },

            ScanProfile.Deep => new DeepScanProfileSettings
            {
                Profile = profile,
                MaxArchiveDepth = Math.Clamp(ClampOr(options.MaxArchiveDepth, settings.ArchiveMaxDepth, 6), 0, 10),
                MaxArchiveEntries = Math.Clamp(ClampOr(options.MaxArchiveEntries, settings.ArchiveMaxEntries, 10_000), 50, 100_000),
                MaxTotalDecompressedBytes = Mb(Math.Clamp(settings.ArchiveMaxDecompressedMB, 256, 16_384)),
                MaxCompressionRatio = 250,
                MaxNestedArchives = 512,
                MaxFileBytes = Mb(options.MaxFileSizeMB > 0 ? options.MaxFileSizeMB : 4_096),
                MaxInMemoryEntryBytes = Mb(128),
                MaxDegreeOfParallelism = dop,
                CpuThrottleDelayMs = options.CpuThrottleDelayMs,
                WorkQueueCapacity = 65_536,
                MaxFindings = 1_000_000,
                PerFileTimeout = TimeSpan.FromMinutes(5),
                PerArchiveTimeout = TimeSpan.FromMinutes(2),
                PerHashTimeout = TimeSpan.FromMinutes(2),
                OverallTimeout = TimeSpan.Zero,
                InspectArchives = settings.DeepScanArchives && options.ScanArchives,
                InspectDocuments = settings.AnalyzeDocuments && options.ScanDocuments,
                InspectBrowserExtensions = settings.AnalyzeBrowserExtensions && options.ScanBrowserExtensions,
                InspectAlternateDataStreams = settings.AnalyzeAlternateDataStreams,
                ResolveRealFileType = true,
                CorrelateEvidence = true,
                EmitStageTelemetry = true,
            },

            _ => Resolve(ScanProfile.Deep, settings, options),
        };
    }

    private static long Mb(long mb) => mb <= 0 ? 0L : mb * 1_048_576L;

    private static int ClampOr(int primary, int fallback, int defaultValue) =>
        primary > 0 ? primary : (fallback > 0 ? fallback : defaultValue);
}
