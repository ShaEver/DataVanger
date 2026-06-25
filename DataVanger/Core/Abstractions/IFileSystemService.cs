using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Filesystem-traversal abstraction. Wraps the resilient enumerator used by
/// the engine so unit tests can substitute an in-memory tree.
/// </summary>
public interface IFileSystemService
{
    /// <summary>
    /// Enumerates files under <paramref name="root"/> without throwing on
    /// access-denied; invokes <paramref name="onAccessDenied"/> instead.
    /// Reparse points are skipped to avoid loops.
    /// </summary>
    IEnumerable<FileInfo> EnumerateFiles(
        string root,
        CancellationToken cancellationToken,
        System.Action<string>? onAccessDenied = null);
}
