using System;
using System.Collections.Concurrent;
using System.Threading;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Per-archive-tree recursion guard.
///
/// Each root archive gets one <see cref="RecursionGuard"/>. It tracks:
///
///   - the current depth into nested containers,
///   - the number of nested archives spawned so far,
///   - identities of already-visited containers (by content hash or
///     normalized path) so a self-referential archive cannot loop forever.
///
/// All public members are thread-safe; archive expansion stages may be parallel.
/// </summary>
public sealed class RecursionGuard
{
    private readonly int _maxDepth;
    private readonly int _maxNestedArchives;
    private readonly ConcurrentDictionary<string, byte> _visited = new(StringComparer.Ordinal);
    private int _nestedArchivesSpawned;

    public RecursionGuard(int maxDepth, int maxNestedArchives)
    {
        _maxDepth = Math.Max(0, maxDepth);
        _maxNestedArchives = Math.Max(0, maxNestedArchives);
    }

    public int MaxDepth => _maxDepth;
    public int MaxNestedArchives => _maxNestedArchives;
    public int NestedArchivesSpawned => Volatile.Read(ref _nestedArchivesSpawned);

    /// <summary>
    /// Returns true when the supplied depth is still within the configured
    /// recursion budget. Depth 0 is the root archive; depth 1 is a nested
    /// archive inside the root, and so on.
    /// </summary>
    public bool DepthAllowed(int depth) => depth <= _maxDepth;

    /// <summary>
    /// Attempts to register a new nested archive. Returns false when the
    /// nested-archive budget is exhausted; in that case the caller MUST stop
    /// expanding and log a <c>RecursionAbort</c>.
    /// </summary>
    public bool TryRegisterNestedArchive()
    {
        if (_maxNestedArchives == 0) return false;
        int updated = Interlocked.Increment(ref _nestedArchivesSpawned);
        if (updated > _maxNestedArchives)
        {
            Interlocked.Decrement(ref _nestedArchivesSpawned);
            return false;
        }
        return true;
    }

    /// <summary>
    /// Registers a content fingerprint. Returns false when this fingerprint
    /// was already seen on the same root tree — the caller must skip the
    /// duplicate to prevent infinite recursion.
    /// </summary>
    public bool TryVisit(string fingerprint)
    {
        if (string.IsNullOrEmpty(fingerprint)) return true;
        return _visited.TryAdd(fingerprint, 1);
    }
}
