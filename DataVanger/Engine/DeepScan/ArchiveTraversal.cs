using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Threading;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Streaming ZIP-family archive walker that enforces every safety budget the
/// deep pipeline cares about:
///
///   - per-archive entry cap,
///   - per-tree decompressed byte cap (zip bombs),
///   - per-entry compression-ratio cap,
///   - per-tree nested-archive cap,
///   - per-archive timeout (via supplied <see cref="CancellationToken"/>),
///   - cycle protection via content fingerprints,
///   - bounded in-memory buffering (entries above the threshold are reported
///     as evidence but not loaded as <see cref="MemoryContentSource"/>).
///
/// The walker yields each admitted entry as <see cref="ArchiveEntryDescriptor"/>;
/// the caller decides whether to enqueue it as a new <see cref="ScanWorkItem"/>
/// or just record evidence. We treat unsupported formats (RAR/7z/CAB without a
/// shipped decoder) as opaque and leave a hook for future plugins.
/// </summary>
public static class ArchiveTraversal
{
    public static IEnumerable<ArchiveEntryDescriptor> Walk(
        Stream stream,
        string logicalRoot,
        int currentDepth,
        DeepScanProfileSettings profile,
        RecursionGuard recursionGuard,
        ZipBombGuard zipBombGuard,
        CancellationToken cancellationToken)
    {
        if (!recursionGuard.DepthAllowed(currentDepth))
        {
            yield return ArchiveEntryDescriptor.Abort(ArchiveAbortReason.MaxDepthReached, logicalRoot);
            yield break;
        }

        if (!TryOpenArchive(stream, out var archive))
        {
            yield return ArchiveEntryDescriptor.Abort(ArchiveAbortReason.MalformedArchive, logicalRoot);
            yield break;
        }

        using (archive)
        {
            int inspected = 0;
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                inspected++;
                if (profile.MaxArchiveEntries > 0 && inspected > profile.MaxArchiveEntries)
                {
                    yield return ArchiveEntryDescriptor.Abort(ArchiveAbortReason.TooManyEntries, logicalRoot);
                    yield break;
                }

                if (IsTraversalAttempt(entry.FullName))
                {
                    yield return ArchiveEntryDescriptor.Suspicious(entry.FullName, logicalRoot, ArchiveSuspicion.PathTraversal);
                    continue;
                }
                if (IsDirectoryEntry(entry)) continue;

                long compressed = SafeLength(entry.CompressedLength);
                long uncompressed = SafeLength(entry.Length);

                var decision = zipBombGuard.TryAdmit(uncompressed, compressed);
                if (!decision.Allowed)
                {
                    yield return ArchiveEntryDescriptor.Abort(MapBombReason(decision.Reason), logicalRoot);
                    yield break;
                }

                // Buffer the entry only if it fits the in-memory budget. Larger
                // entries are still surfaced (for naming evidence) but the
                // caller cannot recursively scan their bytes.
                byte[]? buffer = null;
                bool truncated = false;
                if (uncompressed > 0 && uncompressed <= profile.MaxInMemoryEntryBytes)
                {
                    buffer = TryBuffer(entry, profile.MaxInMemoryEntryBytes, zipBombGuard, cancellationToken, uncompressed, out truncated);
                }

                yield return new ArchiveEntryDescriptor
                {
                    EntryName = entry.FullName,
                    ArchivePath = logicalRoot,
                    CompressedBytes = compressed,
                    UncompressedBytes = uncompressed,
                    Buffer = buffer,
                    Truncated = truncated,
                    Depth = currentDepth,
                };
            }
        }
    }

    /// <summary>
    /// Tracks whether this archive may produce more nested archives. Caller
    /// invokes <see cref="RecursionGuard.TryRegisterNestedArchive"/>.
    /// </summary>
    private static bool TryOpenArchive(Stream stream, out ZipArchive archive)
    {
        try
        {
            archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            return true;
        }
        catch (System.Exception)
        {
            archive = null!;
            return false;
        }
    }

    private static byte[]? TryBuffer(
        ZipArchiveEntry entry,
        long maxBytes,
        ZipBombGuard guard,
        CancellationToken cancellationToken,
        long reservedBytes,
        out bool truncated)
    {
        truncated = false;
        try
        {
            using var s = entry.Open();
            using var ms = new MemoryStream();
            byte[] tmp = new byte[64 * 1024];
            long total = 0;
            int read;
            while ((read = s.Read(tmp, 0, tmp.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                long before = total;
                total += read;

                // TryAdmit already reserved the archive header's advertised
                // uncompressed length. Only charge extra streamed bytes when
                // an entry produces more payload than it declared.
                if (total > reservedBytes)
                {
                    long extra = total - Math.Max(before, reservedBytes);
                    if (extra > 0 && !guard.ReportStreamedBytes(extra))
                    {
                        truncated = true;
                        break;
                    }
                }

                if (total > maxBytes)
                {
                    truncated = true;
                    break;
                }
                ms.Write(tmp, 0, read);
            }
            return ms.ToArray();
        }
        catch (System.Exception)
        {
            return null;
        }
    }

    private static bool IsDirectoryEntry(ZipArchiveEntry entry) =>
        entry.FullName.EndsWith("/", StringComparison.Ordinal) ||
        entry.FullName.EndsWith("\\", StringComparison.Ordinal);

    private static bool IsTraversalAttempt(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name.Contains("..", StringComparison.Ordinal)) return true;
        if (name.StartsWith("/", StringComparison.Ordinal)) return true;
        if (name.Length >= 2 && name[1] == ':') return true; // absolute Windows path
        return false;
    }

    private static long SafeLength(long value) => value < 0 ? 0 : value;

    private static ArchiveAbortReason MapBombReason(ZipBombReason reason) => reason switch
    {
        ZipBombReason.TooManyEntries           => ArchiveAbortReason.TooManyEntries,
        ZipBombReason.RatioExceeded            => ArchiveAbortReason.CompressionRatioExceeded,
        ZipBombReason.DecompressedSizeExceeded => ArchiveAbortReason.DecompressedSizeExceeded,
        _                                      => ArchiveAbortReason.MalformedArchive,
    };
}

public sealed class ArchiveEntryDescriptor
{
    public string EntryName { get; init; } = "";
    public string ArchivePath { get; init; } = "";
    public long CompressedBytes { get; init; }
    public long UncompressedBytes { get; init; }
    public byte[]? Buffer { get; init; }
    public bool Truncated { get; init; }
    public int Depth { get; init; }

    public ArchiveAbortReason AbortReason { get; init; }
    public ArchiveSuspicion Suspicion { get; init; }

    public bool IsAbort => AbortReason != ArchiveAbortReason.None;
    public bool IsSuspicious => Suspicion != ArchiveSuspicion.None;

    public static ArchiveEntryDescriptor Abort(ArchiveAbortReason reason, string archivePath) =>
        new() { AbortReason = reason, ArchivePath = archivePath };

    public static ArchiveEntryDescriptor Suspicious(string entryName, string archivePath, ArchiveSuspicion suspicion) =>
        new() { EntryName = entryName, ArchivePath = archivePath, Suspicion = suspicion };
}

public enum ArchiveAbortReason
{
    None,
    MalformedArchive,
    MaxDepthReached,
    TooManyEntries,
    DecompressedSizeExceeded,
    CompressionRatioExceeded,
    NestedArchiveBudgetExhausted,
    Timeout,
}

public enum ArchiveSuspicion
{
    None,
    PathTraversal,
}
