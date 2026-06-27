using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// Default <see cref="IHashService"/> backed by an on-disk JSON cache.
///
/// Cache keys include the path, last-write timestamp and file length, so any
/// modification invalidates the entry. Old cache files in the legacy
/// <c>path|ticks|length =&gt; hash</c> format are upgraded transparently on
/// load to avoid losing accumulated cache hits after the refactor.
/// </summary>
public sealed class Sha256HashService : IHashService
{
    // 80 KB pooled read buffer — matches StreamHasher.DefaultBufferSize and the
    // Stream.CopyTo default, large enough to amortise syscall overhead.
    private const int HashBufferSize = 81_920;

    private readonly string _cachePath;
    private ConcurrentDictionary<string, HashCacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _writeLock = new();

    public Sha256HashService(string cachePath)
    {
        _cachePath = cachePath;
        Load();
    }

    public string? ComputeSha256(FileInfo file, out bool cacheHit)
    {
        cacheHit = false;
        try
        {
            if (_cache.TryGetValue(file.FullName, out var cached)
                && cached.LastWriteUtcTicks == file.LastWriteTimeUtc.Ticks
                && cached.Length == file.Length
                && cached.Hash.Length == 64)
            {
                cacheHit = true;
                return cached.Hash;
            }

            // FASE 3 — I/O efficiency. Hashing runs on every eligible file, so this
            // is the hottest IO path in the scan. Three changes over the old
            // SHA256.ComputeHash(stream) call (which used a 4 KB internal buffer
            // and a fresh allocation per file):
            //   1. FileOptions.SequentialScan hints the OS to prefetch pages.
            //   2. An 80 KB buffer is rented from ArrayPool and recycled.
            //   3. IncrementalHash streams the file so it is never materialised.
            // This mirrors the proven StreamHasher pattern used by the deep pipeline.
            using var fs = new FileStream(
                file.FullName,
                new FileStreamOptions
                {
                    Mode = FileMode.Open,
                    Access = FileAccess.Read,
                    Share = FileShare.Read,
                    Options = FileOptions.SequentialScan,
                    BufferSize = HashBufferSize,
                });
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(HashBufferSize);
            string hash;
            try
            {
                int n;
                while ((n = fs.Read(buffer, 0, buffer.Length)) > 0)
                    sha.AppendData(buffer, 0, n);
                hash = Convert.ToHexString(sha.GetHashAndReset());
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: false);
            }
            _cache[file.FullName] = new HashCacheEntry
            {
                Path = file.FullName,
                Hash = hash,
                LastWriteUtcTicks = file.LastWriteTimeUtc.Ticks,
                Length = file.Length,
                LastScan = DateTime.Now,
            };
            return hash;
        }
        catch (System.Exception)
        {
            return null;
        }
    }

    public void TouchScore(string fullPath, int lastScore, bool knownSafe)
        => TouchScore(fullPath, lastScore, knownSafe, null);

    // Beta 10 — fingerprint-aware overload. Records the signature fingerprint in
    // effect so the clean-file cache can later verify it is unchanged.
    public void TouchScore(string fullPath, int lastScore, bool knownSafe, string? signatureFingerprint)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return;
        lock (_writeLock)
        {
            if (!_cache.TryGetValue(fullPath, out var entry)) return;
            entry.LastScan = DateTime.Now;
            entry.LastScore = lastScore;
            entry.WasKnownSafe = knownSafe;
            if (signatureFingerprint != null) entry.SignatureFingerprint = signatureFingerprint;
            _cache[fullPath] = entry;
        }
    }

    /// <summary>
    /// Beta 10 — clean-file result cache. Returns true only when the file is
    /// byte-identical to a previously cached entry (same last-write + length) that
    /// was determined <b>known-safe</b> under the <b>same</b> signature fingerprint.
    /// In that case the file can be skipped without re-analysis.
    ///
    /// Safety: this never bypasses a known-malicious check. A clean-skip requires
    /// <see cref="HashCacheEntry.WasKnownSafe"/> (the prior verdict was benign),
    /// <see cref="HashCacheEntry.LastScore"/> == 0, an unchanged
    /// <paramref name="signatureFingerprint"/> (any blacklist/whitelist/YARA change
    /// invalidates it), and an unchanged file identity. An empty fingerprint never
    /// matches.
    /// </summary>
    public bool TryCleanSkip(FileInfo file, string signatureFingerprint)
    {
        if (file is null || string.IsNullOrEmpty(signatureFingerprint)) return false;
        try
        {
            if (!_cache.TryGetValue(file.FullName, out var entry)) return false;
            return entry.WasKnownSafe
                && entry.LastScore == 0
                && entry.LastWriteUtcTicks == file.LastWriteTimeUtc.Ticks
                && entry.Length == file.Length
                && string.Equals(entry.SignatureFingerprint, signatureFingerprint, StringComparison.Ordinal);
        }
        catch (System.Exception)
        {
            return false;
        }
    }

    public void Persist()
    {
        try
        {
            var pruned = _cache.Values
                .Where(x => { try { return File.Exists(x.Path); } catch (System.Exception) { return false; } })
                .OrderByDescending(x => x.LastScan)
                .Take(250_000)
                .ToList();
            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(_cachePath, JsonSerializer.Serialize(pruned, opts), Encoding.UTF8);
        }
        catch (System.Exception) { /* never let cache persistence crash a scan */ }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_cachePath)) return;
            var raw = File.ReadAllText(_cachePath);
            var list = JsonSerializer.Deserialize<System.Collections.Generic.List<HashCacheEntry>>(raw);
            if (list != null)
            {
                _cache = new ConcurrentDictionary<string, HashCacheEntry>(
                    list.Where(x => !string.IsNullOrWhiteSpace(x.Path) && !string.IsNullOrWhiteSpace(x.Hash))
                        .GroupBy(x => x.Path, StringComparer.OrdinalIgnoreCase)
                        .Select(g => g.OrderByDescending(x => x.LastScan).First())
                        .ToDictionary(x => x.Path, x => x, StringComparer.OrdinalIgnoreCase),
                    StringComparer.OrdinalIgnoreCase);
                return;
            }
        }
        catch (System.Exception)
        {
            // Old format: path|ticks|length => hash
            try
            {
                var raw = File.ReadAllText(_cachePath);
                var old = JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, string>>(raw);
                if (old != null)
                {
                    foreach (var kv in old)
                    {
                        var parts = kv.Key.Split('|');
                        if (parts.Length < 3) continue;
                        if (!long.TryParse(parts[1], out var ticks)) continue;
                        if (!long.TryParse(parts[2], out var len)) continue;
                        _cache[parts[0]] = new HashCacheEntry
                        {
                            Path = parts[0],
                            Hash = kv.Value,
                            LastWriteUtcTicks = ticks,
                            Length = len,
                            LastScan = DateTime.Now.AddDays(-1),
                            LastScore = 0
                        };
                    }
                }
            }
            catch (System.Exception) { _cache = new ConcurrentDictionary<string, HashCacheEntry>(StringComparer.OrdinalIgnoreCase); }
        }
    }

    public sealed class HashCacheEntry
    {
        public string Path { get; set; } = "";
        public string Hash { get; set; } = "";
        public long LastWriteUtcTicks { get; set; }
        public long Length { get; set; }
        public DateTime LastScan { get; set; }
        public int LastScore { get; set; }
        public bool WasKnownSafe { get; set; }

        // Beta 10 — signature/rule fingerprint in effect when this verdict was
        // recorded. The clean-file cache only trusts an entry whose fingerprint
        // still matches, so any signature change forces a full rescan.
        public string SignatureFingerprint { get; set; } = "";
    }
}
