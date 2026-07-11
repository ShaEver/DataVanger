using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace DataVanger.Infrastructure;

/// <summary>
/// Beta 10 — lightweight, thread-safe per-stage wall-time accumulator for the
/// scan pipeline. Purely additive instrumentation: it measures where scan time
/// is spent (enumeration, hashing, detection pipeline, persistence/process
/// collection) without altering any scan behaviour, threshold, or verdict.
///
/// Overhead is bounded to two <see cref="Stopwatch.GetTimestamp"/> reads plus a
/// lock-free dictionary update per measured region, so it is safe to leave on in
/// the hot path. Stage timings are reported via diagnostics/report only and never
/// feed the classifier or anti-false-positive logic.
///
/// Beta 11 Extension: Per-item metrics tracking (optional) for detailed performance
/// analysis. Each stage can track per-file elapsed times, file sizes, and file types
/// to compute percentiles (P50, P95) without per-item allocations.
/// </summary>
public sealed class ScanStageProfiler
{
    private readonly ConcurrentDictionary<string, long> _ticks = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, long> _counts = new(StringComparer.Ordinal);

    // Per-item metrics: stage -> list of (elapsedTicks, fileSize)
    private readonly ConcurrentDictionary<string, ConcurrentBag<(long ticks, int fileSize)>> _perItemMetrics =
        new(StringComparer.Ordinal);

    /// <summary>Adds an already-measured interval (in <see cref="Stopwatch"/> ticks) to a stage.</summary>
    public void Add(string stage, long elapsedTicks, long count = 1)
    {
        if (string.IsNullOrEmpty(stage)) return;
        if (elapsedTicks > 0) _ticks.AddOrUpdate(stage, elapsedTicks, (_, v) => v + elapsedTicks);
        if (count != 0) _counts.AddOrUpdate(stage, count, (_, v) => v + count);
    }

    /// <summary>
    /// Starts measuring a stage. Dispose the returned scope (e.g. via <c>using</c>
    /// or an explicit <c>Dispose()</c>) to record the elapsed interval.
    /// </summary>
    public Scope Measure(string stage) => new(this, stage);

    /// <summary>
    /// Records an individual item's elapsed time and file size for a stage.
    /// Used for computing per-stage statistics (P50, P95, max per item).
    /// </summary>
    public void RecordItemMetrics(string stage, long elapsedTicks, int fileSize)
    {
        if (string.IsNullOrEmpty(stage) || elapsedTicks < 0) return;
        var bag = _perItemMetrics.GetOrAdd(stage, _ => new ConcurrentBag<(long, int)>());
        bag.Add((elapsedTicks, fileSize));
    }

    /// <summary>
    /// Gets per-item statistics (P50, P95, Max, Avg file size) for a stage.
    /// Returns null if stage has no recorded items.
    /// </summary>
    public PerItemMetricsSnapshot? GetPerItemSnapshot(string stage)
    {
        if (!_perItemMetrics.TryGetValue(stage, out var bag) || bag.Count == 0)
            return null;

        var items = bag.ToList();
        if (items.Count == 0) return null;

        var sortedTicks = items.Select(x => x.ticks).OrderBy(x => x).ToList();
        var p50Idx = (items.Count - 1) * 50 / 100;
        var p95Idx = (items.Count - 1) * 95 / 100;
        var p50Ticks = sortedTicks[p50Idx];
        var p95Ticks = sortedTicks[p95Idx];
        var maxTicks = sortedTicks[sortedTicks.Count - 1];
        var totalTicks = sortedTicks.Sum(x => (long)x);
        var avgFileSize = items.Count > 0 ? items.Average(x => x.fileSize) : 0;

        return new PerItemMetricsSnapshot(
            Total: TimeSpan.FromSeconds((double)totalTicks / Stopwatch.Frequency),
            Count: items.Count,
            P50: TimeSpan.FromSeconds((double)p50Ticks / Stopwatch.Frequency),
            P95: TimeSpan.FromSeconds((double)p95Ticks / Stopwatch.Frequency),
            Max: TimeSpan.FromSeconds((double)maxTicks / Stopwatch.Frequency),
            AvgFileSize: (long)avgFileSize);
    }

    /// <summary>Per-stage totals, ordered by descending elapsed time.</summary>
    public IReadOnlyList<StageTiming> Snapshot() =>
        _ticks
            .Select(kv => new StageTiming(
                kv.Key,
                TimeSpan.FromSeconds((double)kv.Value / Stopwatch.Frequency),
                _counts.TryGetValue(kv.Key, out var c) ? c : 0))
            .OrderByDescending(x => x.Elapsed)
            .ToList();

    public readonly record struct StageTiming(string Stage, TimeSpan Elapsed, long Count);

    public readonly record struct PerItemMetricsSnapshot(
        TimeSpan Total,
        long Count,
        TimeSpan P50,
        TimeSpan P95,
        TimeSpan Max,
        long AvgFileSize)
    {
        public double FilesPerSecond => Count > 0 && Total.TotalSeconds > 0 ? Count / Total.TotalSeconds : 0;
    }

    /// <summary>Disposable measurement region. A struct to avoid per-file allocations.</summary>
    public readonly struct Scope : IDisposable
    {
        private readonly ScanStageProfiler? _owner;
        private readonly string _stage;
        private readonly long _start;

        internal Scope(ScanStageProfiler owner, string stage)
        {
            _owner = owner;
            _stage = stage;
            _start = Stopwatch.GetTimestamp();
        }

        /// <summary>
        /// Raw <see cref="Stopwatch"/> ticks elapsed since the scope started. Intended to be read
        /// right after <see cref="Dispose"/> and fed to <see cref="RecordItemMetrics"/> (which divides
        /// by <see cref="Stopwatch.Frequency"/>). Re-reads the timestamp, so it is a near-identical
        /// superset of the interval committed by Dispose — adequate for per-item telemetry.
        /// </summary>
        public long ElapsedTicks => Stopwatch.GetTimestamp() - _start;

        /// <summary>Elapsed wall-time since the scope started (telemetry convenience).</summary>
        public TimeSpan Elapsed => TimeSpan.FromSeconds((double)ElapsedTicks / Stopwatch.Frequency);

        public void Dispose() => _owner?.Add(_stage, Stopwatch.GetTimestamp() - _start);
    }
}
