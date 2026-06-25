using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Probes a file path to decide whether it is safe to hand off to the
/// scan engine. Implementations must:
///   - Never lock the file for more than a short read attempt.
///   - Never throw — failures must be surfaced as a
///     <see cref="FileStabilityResult"/> with a non-Stable outcome.
///   - Honor cancellation.
/// </summary>
public interface IFileStabilityProbe
{
    Task<FileStabilityResult> ProbeAsync(string path, long maxSizeBytes, CancellationToken cancellationToken);
}
