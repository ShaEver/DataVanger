using System.Threading;

namespace DataVanger.Memory;

/// <summary>
/// Top-level memory scanner contract. Implementations are expected to
/// be safe to call from any thread and to never throw on platform /
/// permission failures — they should return a degraded result instead.
/// </summary>
public interface IMemoryScanner
{
    bool IsSupported { get; }

    MemoryScanResult Scan(MemoryScannerOptions options, CancellationToken cancellationToken);
}
