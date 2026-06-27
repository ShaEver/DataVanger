using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// Default <see cref="IFileSystemService"/> — a BFS walker that swallows
/// per-directory failures and reports access-denied folders without
/// terminating the scan. Reparse points are skipped to prevent loops.
/// </summary>
public sealed class ResilientFileSystemService : IFileSystemService
{
    /// <summary>
    /// Defensive depth ceiling for pathological filesystems. Reparse points are
    /// already skipped, but extremely deep hand-crafted directory trees can
    /// still starve memory and cancellation responsiveness. Callers can override
    /// via <see cref="EnumerateFiles(string, CancellationToken, Action{string}, int)"/>.
    /// </summary>
    public const int DefaultMaxDepth = 512;

    public IEnumerable<FileInfo> EnumerateFiles(
        string root,
        CancellationToken cancellationToken,
        Action<string>? onAccessDenied = null)
        => EnumerateFiles(root, cancellationToken, onAccessDenied, DefaultMaxDepth);

    /// <summary>
    /// Depth-limited overload. <paramref name="maxDepth"/> values &lt;= 0 are
    /// treated as unbounded (legacy behavior).
    /// </summary>
    public IEnumerable<FileInfo> EnumerateFiles(
        string root,
        CancellationToken cancellationToken,
        Action<string>? onAccessDenied,
        int maxDepth)
    {
        var queue = new Queue<(DirectoryInfo Dir, int Depth)>();
        try { queue.Enqueue((new DirectoryInfo(root), 0)); }
        catch (System.Exception) { yield break; }

        while (queue.Count > 0)
        {
            if (cancellationToken.IsCancellationRequested) yield break;
            var (dir, depth) = queue.Dequeue();

            IEnumerable<FileInfo> files = Array.Empty<FileInfo>();
            try { files = dir.EnumerateFiles(); }
            catch (UnauthorizedAccessException) { onAccessDenied?.Invoke(dir.FullName); }
            catch (IOException) { }

            foreach (var f in files)
            {
                if (cancellationToken.IsCancellationRequested) yield break;
                yield return f;
            }

            // Stop descending once the configured maxDepth is reached. We
            // still emit files at the boundary; we just stop adding new
            // subdirectories beyond it.
            if (maxDepth > 0 && depth >= maxDepth) continue;

            IEnumerable<DirectoryInfo> subs = Array.Empty<DirectoryInfo>();
            try { subs = dir.EnumerateDirectories(); }
            catch (UnauthorizedAccessException) { onAccessDenied?.Invoke(dir.FullName); }
            catch (IOException) { }

            foreach (var sub in subs)
            {
                try
                {
                    if ((sub.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    queue.Enqueue((sub, depth + 1));
                }
                catch (UnauthorizedAccessException)
                {
                    // Protected directory - skip and continue enumeration.
                }
                catch (IOException)
                {
                    // Locked/unreadable directory - skip and continue enumeration.
                }
            }
        }
    }
}
