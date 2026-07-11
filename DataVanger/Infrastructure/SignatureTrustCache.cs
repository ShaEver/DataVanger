using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using DataVanger.Core;

namespace DataVanger.Infrastructure;

/// <summary>
/// Bounded diagnostic record of signature checks. It deliberately exposes no lookup:
/// Authenticode is verified against the current file for every security decision.
/// </summary>
internal sealed class SignatureTrustCache
{
    private const int SchemaVersion = 1;
    private const int MaxCacheBytes = 4 * 1024 * 1024;
    private const int MaxEntries = 10_000;
    private readonly string _cachePath;
    private readonly List<SignatureCheckObservation> _entries = new();
    private readonly object _sync = new();

    public SignatureTrustCache(string cachePath)
    {
        _cachePath = cachePath;
        LoadObservations();
    }

    public CacheHealth Health { get; private set; } = CacheHealth.Healthy;

    public void Observe(FileInfo file, SignatureVerificationResult result)
    {
        if (file is null || result is null) return;
        lock (_sync)
        {
            _entries.Add(new SignatureCheckObservation
            {
                Path = file.FullName,
                Length = file.Length,
                LastSeenUtc = DateTime.UtcNow,
                VerificationAttempted = true,
                Source = result.Source.ToString(),
            });
            if (_entries.Count > MaxEntries) _entries.RemoveRange(0, _entries.Count - MaxEntries);
        }
    }

    public void Persist()
    {
        try
        {
            List<SignatureCheckObservation> snapshot;
            lock (_sync) snapshot = _entries.TakeLast(MaxEntries).ToList();
            var payload = JsonSerializer.Serialize(new CacheEnvelope { Version = SchemaVersion, Entries = snapshot });
            if (Encoding.UTF8.GetByteCount(payload) > MaxCacheBytes) { MarkDegraded("persist-size-limit"); return; }
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
            if (envelope?.Version != SchemaVersion || envelope.Entries is null || envelope.Entries.Count > MaxEntries
                || envelope.Entries.Any(x => string.IsNullOrWhiteSpace(x.Path) || x.Path.Length > 32_768 || x.Length < 0))
            {
                MarkDegraded("invalid-schema-or-entry");
                return;
            }
            // Historical observations are intentionally not loaded into a lookup.
        }
        catch (Exception) { MarkDegraded("load-failed"); }
    }

    private void MarkDegraded(string reason) => Health = new CacheHealth(true, reason);

    internal sealed record CacheHealth(bool IsDegraded, string Reason)
    {
        public static CacheHealth Healthy { get; } = new(false, "");
    }

    private sealed class CacheEnvelope
    {
        public int Version { get; set; }
        public List<SignatureCheckObservation> Entries { get; set; } = new();
    }

    private sealed class SignatureCheckObservation
    {
        public string Path { get; set; } = "";
        public long Length { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public bool VerificationAttempted { get; set; }
        public string Source { get; set; } = "";
    }
}
