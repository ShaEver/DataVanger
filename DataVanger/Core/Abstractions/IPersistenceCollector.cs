using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Collects Windows persistence indicators (Run keys, scheduled tasks,
/// startup folders, services, WMI subscriptions).
///
/// The result is a snapshot — modules cross-reference it via
/// <see cref="Domain.ScanContext.PersistenceExactPaths"/>.
/// </summary>
public interface IPersistenceCollector
{
    /// <summary>Returns raw persistence entries (lower-cased).</summary>
    Task<IReadOnlyCollection<string>> CollectAsync(CancellationToken cancellationToken);
}
