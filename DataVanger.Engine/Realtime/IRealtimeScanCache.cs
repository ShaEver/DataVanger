using DataVanger.Shared.Realtime;

namespace DataVanger.Engine.Realtime;

/// <summary>
/// Short-lived, in-memory duplicate-scan cache. The cache:
///   - Avoids re-scanning unchanged files within a configured window.
///   - MUST invalidate entries when length / last-write / hash changes.
///   - MUST NEVER override a known-bad hash — callers (decision engine
///     / dispatcher) keep blacklist precedence.
///   - On any failure (corrupted entry, eviction race) MUST degrade to
///     "miss" so the orchestrator re-scans, never to "trust".
/// </summary>
public interface IRealtimeScanCache
{
    bool TryGet(RealtimeScanRequest request, out RealtimeScanResult? cached);
    void Store(RealtimeScanRequest request, RealtimeScanResult result);
    int Count { get; }
    void Clear();
}
