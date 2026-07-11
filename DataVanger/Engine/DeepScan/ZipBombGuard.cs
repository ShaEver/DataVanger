using System;
using System.Threading;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Defends archive expansion against zip bombs and pathological compression.
///
/// One <see cref="ZipBombGuard"/> instance is created per root archive tree
/// and shared across every nested archive that grows out of it. It tracks
/// three independent budgets:
///
///   1. Cumulative decompressed bytes across the tree.
///   2. Number of entries inspected.
///   3. Per-entry compression ratio.
///
/// All updates are thread-safe; archive walkers may extract entries in parallel
/// inside a single root archive when supported.
/// </summary>
public sealed class ZipBombGuard
{
    private readonly long _maxTotalDecompressedBytes;
    private readonly int  _maxEntries;
    private readonly int  _maxCompressionRatio;
    private long _decompressedBytes;
    private int  _entriesInspected;

    public ZipBombGuard(long maxTotalDecompressedBytes, int maxEntries, int maxCompressionRatio)
    {
        _maxTotalDecompressedBytes = Math.Max(0, maxTotalDecompressedBytes);
        _maxEntries = Math.Max(0, maxEntries);
        _maxCompressionRatio = Math.Max(1, maxCompressionRatio);
    }

    public long MaxTotalDecompressedBytes => _maxTotalDecompressedBytes;
    public int  MaxEntries                => _maxEntries;
    public int  MaxCompressionRatio       => _maxCompressionRatio;

    public long DecompressedBytes => Interlocked.Read(ref _decompressedBytes);
    public int  EntriesInspected  => Volatile.Read(ref _entriesInspected);

    /// <summary>
    /// Reserves capacity for an entry that reports <paramref name="entryUncompressedBytes"/>
    /// of uncompressed payload and <paramref name="entryCompressedBytes"/> of stored data.
    /// Returns <see cref="ZipBombDecision.Allow"/> when extraction may proceed.
    /// </summary>
    public ZipBombDecision TryAdmit(long entryUncompressedBytes, long entryCompressedBytes)
    {
        int entries = Interlocked.Increment(ref _entriesInspected);
        if (_maxEntries > 0 && entries > _maxEntries)
            return ZipBombDecision.Deny(ZipBombReason.TooManyEntries);

        if (entryUncompressedBytes < 0) entryUncompressedBytes = 0;
        if (entryCompressedBytes <= 0) entryCompressedBytes = 1;

        long ratio = entryUncompressedBytes / entryCompressedBytes;
        if (ratio > _maxCompressionRatio)
            return ZipBombDecision.Deny(ZipBombReason.RatioExceeded);

        long total = Interlocked.Add(ref _decompressedBytes, entryUncompressedBytes);
        if (_maxTotalDecompressedBytes > 0 && total > _maxTotalDecompressedBytes)
        {
            // Roll the reservation back so the next caller sees an honest counter.
            Interlocked.Add(ref _decompressedBytes, -entryUncompressedBytes);
            return ZipBombDecision.Deny(ZipBombReason.DecompressedSizeExceeded);
        }

        return ZipBombDecision.Allow;
    }

    /// <summary>
    /// Reports <paramref name="bytesWritten"/> of extra payload actually
    /// produced by streaming decompression (used when an entry lied about
    /// its uncompressed length). Returns true while the cumulative budget
    /// is still honored; false means the caller must stop reading.
    /// </summary>
    public bool ReportStreamedBytes(long bytesWritten)
    {
        if (bytesWritten <= 0) return true;
        long total = Interlocked.Add(ref _decompressedBytes, bytesWritten);
        return _maxTotalDecompressedBytes == 0 || total <= _maxTotalDecompressedBytes;
    }
}

public enum ZipBombReason
{
    None,
    TooManyEntries,
    RatioExceeded,
    DecompressedSizeExceeded,
}

public readonly record struct ZipBombDecision(bool Allowed, ZipBombReason Reason)
{
    public static ZipBombDecision Allow { get; } = new(true, ZipBombReason.None);
    public static ZipBombDecision Deny(ZipBombReason reason) => new(false, reason);
}
