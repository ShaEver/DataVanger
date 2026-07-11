using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// SHA-256 service with an optional, bounded on-disk observation cache.
/// The cache is strictly diagnostic: every call hashes the current file bytes and
/// no cache field can grant a safe verdict or skip a detection stage.
/// </summary>
public sealed class Sha256HashService : IHashService
{
    private const int HashBufferSize = 81_920;
    private const int CacheSchemaVersion = 1;
    private const int MaxCacheBytes = 8 * 1024 * 1024;
    private const int MaxEntries = 10_000;

    private readonly string _cachePath;
    private ConcurrentDictionary<string, HashCacheEntry> _observations = new(StringComparer.OrdinalIgnoreCase);

    public Sha256HashService(string cachePath)
    {
        _cachePath = cachePath;
        LoadObservations();
    }

    /// <summary>Load failures are observable but always fail closed to an empty cache.</summary>
    public CacheHealth Health { get; private set; } = CacheHealth.Healthy;

    public string? ComputeSha256(FileInfo file, out bool cacheHit)
    {
        // mtime + length cannot establish immutable content. Never reuse a stored hash.
        cacheHit = false;
        try
        {
            using var fs = new FileStream(file.FullName, new FileStreamOptions
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
            finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: false); }

            _observations[file.FullName] = new HashCacheEntry
            {
                Path = file.FullName,
                Hash = hash,
                LastWriteUtcTicks = file.LastWriteTimeUtc.Ticks,
                Length = file.Length,
                LastScan = DateTime.UtcNow,
            };
            return hash;
        }
        catch (Exception) { return null; }
    }

    public void TouchScore(string fullPath, int lastScore, bool knownSafe)
    {
        // Retained for compatibility with the scan's diagnostic/reputation bookkeeping.
        // Neither score nor knownSafe is ever read to alter scan behavior.
        if (string.IsNullOrWhiteSpace(fullPath)) return;
        if (_observations.TryGetValue(fullPath, out var entry))
        {
            entry.LastScan = DateTime.UtcNow;
            entry.LastScore = lastScore;
            _observations[fullPath] = entry;
        }
    }

    public void Persist()
    {
        try
        {
            var entries = _observations.Values
                .Where(IsValidEntry)
                .OrderByDescending(x => x.LastScan)
                .Take(MaxEntries)
                .ToList();
            var payload = JsonSerializer.Serialize(new CacheEnvelope { Version = CacheSchemaVersion, Entries = entries });
            if (Encoding.UTF8.GetByteCount(payload) > MaxCacheBytes)
            {
                MarkDegraded("persist-size-limit");
                return;
            }
            string? dir = Path.GetDirectoryName(_cachePath);
            if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
            string temp = _cachePath + ".tmp";
            File.WriteAllText(temp, payload, Encoding.UTF8);
            File.Move(temp, _cachePath, overwrite: true);
        }
        catch (Exception) { MarkDegraded("persist-failed"); }
    }

    private void LoadObservations()
    {
        try
        {
            if (!File.Exists(_cachePath)) return;
            if (new FileInfo(_cachePath).Length > MaxCacheBytes) { MarkDegraded("load-size-limit"); return; }
            var envelope = JsonSerializer.Deserialize<CacheEnvelope>(File.ReadAllText(_cachePath, Encoding.UTF8));
            if (envelope?.Version != CacheSchemaVersion || envelope.Entries is null || envelope.Entries.Count > MaxEntries)
            {
                MarkDegraded("invalid-schema-or-entry-limit");
                return;
            }
            if (envelope.Entries.Any(x => !IsValidEntry(x))
                || envelope.Entries.GroupBy(x => x.Path, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() != 1))
            {
                MarkDegraded("invalid-or-duplicate-entry");
                return;
            }
            _observations = new ConcurrentDictionary<string, HashCacheEntry>(
                envelope.Entries.ToDictionary(x => x.Path, x => x, StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception) { MarkDegraded("load-failed"); }
    }

    private static bool IsValidEntry(HashCacheEntry x) =>
        !string.IsNullOrWhiteSpace(x.Path) && x.Path.Length <= 32_768
        && x.Hash.Length == 64 && x.Hash.All(Uri.IsHexDigit)
        && x.Length >= 0;

    private void MarkDegraded(string reason)
    {
        _observations = new ConcurrentDictionary<string, HashCacheEntry>(StringComparer.OrdinalIgnoreCase);
        Health = new CacheHealth(true, reason);
    }

    public sealed record CacheHealth(bool IsDegraded, string Reason)
    {
        public static CacheHealth Healthy { get; } = new(false, "");
    }

    private sealed class CacheEnvelope
    {
        public int Version { get; set; }
        public List<HashCacheEntry> Entries { get; set; } = new();
    }

    public sealed class HashCacheEntry
    {
        public string Path { get; set; } = "";
        public string Hash { get; set; } = "";
        public long LastWriteUtcTicks { get; set; }
        public long Length { get; set; }
        public DateTime LastScan { get; set; }
        public int LastScore { get; set; }
    }
}
