using System;
using System.Collections.Generic;
using DataVanger.Shared.Realtime;

namespace DataVanger.Engine.Realtime;

/// <summary>
/// Bounded in-memory implementation of <see cref="IRealtimeScanCache"/>.
///
/// Key composition (anti-FP invariants):
///   - Normalized path (case-insensitive on Windows-like inputs).
///   - File length AND last-write timestamp (any drift => miss).
///   - SHA-256 hash if available (mismatch => miss).
///
/// Entries beyond <c>maxEntries</c> evict the oldest. Entries older
/// than <c>lifetime</c> are also evicted. Eviction errors degrade to
/// "miss" so the orchestrator re-scans.
/// </summary>
public sealed class InMemoryRealtimeScanCache : IRealtimeScanCache
{
    private readonly object _gate = new();
    private readonly LinkedList<Entry> _order = new();
    private readonly Dictionary<string, LinkedListNode<Entry>> _byKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _lifetime;
    private readonly int _maxEntries;
    private readonly Func<DateTimeOffset> _utcNow;

    public InMemoryRealtimeScanCache(TimeSpan lifetime, int maxEntries, Func<DateTimeOffset>? utcNow = null)
    {
        if (lifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(lifetime));
        if (maxEntries <= 0) throw new ArgumentOutOfRangeException(nameof(maxEntries));
        _lifetime = lifetime;
        _maxEntries = maxEntries;
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public int Count
    {
        get { lock (_gate) return _byKey.Count; }
    }

    public bool TryGet(RealtimeScanRequest request, out RealtimeScanResult? cached)
    {
        cached = null;
        if (request is null) return false;
        var key = BuildKey(request);
        if (key is null) return false;

        lock (_gate)
        {
            if (!_byKey.TryGetValue(key, out var node)) return false;
            var entry = node.Value;
            if (_utcNow() - entry.StoredAtUtc > _lifetime)
            {
                _order.Remove(node);
                _byKey.Remove(key);
                return false;
            }
            // Anti-FP: cache hits NEVER override blacklist semantics.
            // ConfirmedMalware entries are deliberately re-served so the
            // decision engine still requests quarantine; clean entries
            // are served as before — but heuristic verdicts also re-
            // served verbatim, because a fresh observation is the
            // decision engine's responsibility, not the cache's.
            cached = new RealtimeScanResult
            {
                Path = entry.Result.Path,
                Verdict = entry.Result.Verdict,
                IsConfirmedMalware = entry.Result.IsConfirmedMalware,
                FromCache = true,
                Failed = entry.Result.Failed,
                FailureReason = entry.Result.FailureReason,
                CompletedAtUtc = entry.Result.CompletedAtUtc,
                Message = entry.Result.Message,
            };
            return true;
        }
    }

    public void Store(RealtimeScanRequest request, RealtimeScanResult result)
    {
        if (request is null || result is null) return;
        // Anti-FP: do not cache failed results — re-scan next time so a
        // transient I/O error never persists as a "trusted" verdict.
        if (result.Failed) return;

        var key = BuildKey(request);
        if (key is null) return;

        lock (_gate)
        {
            if (_byKey.TryGetValue(key, out var existing))
            {
                _order.Remove(existing);
                _byKey.Remove(key);
            }
            var entry = new Entry(key, result, _utcNow());
            var node = _order.AddLast(entry);
            _byKey[key] = node;

            while (_byKey.Count > _maxEntries && _order.First is { } first)
            {
                _byKey.Remove(first.Value.Key);
                _order.RemoveFirst();
            }
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _byKey.Clear();
            _order.Clear();
        }
    }

    private static string? BuildKey(RealtimeScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Path)) return null;
        // Cache key requires at least length OR hash to ensure metadata
        // changes invalidate the entry. If neither is observed (file
        // never stabilized), refuse to cache so the next event re-scans.
        if (request.FileLength < 0 && string.IsNullOrEmpty(request.Sha256)) return null;

        var lastWriteTicks = request.LastWriteUtc?.UtcTicks ?? 0L;
        return string.Concat(
            request.Path.ToUpperInvariant(),
            "|", request.FileLength.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "|", lastWriteTicks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "|", request.Sha256 ?? string.Empty);
    }

    private readonly struct Entry
    {
        public Entry(string key, RealtimeScanResult result, DateTimeOffset storedAtUtc)
        {
            Key = key;
            Result = result;
            StoredAtUtc = storedAtUtc;
        }
        public string Key { get; }
        public RealtimeScanResult Result { get; }
        public DateTimeOffset StoredAtUtc { get; }
    }
}
