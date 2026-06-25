using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using DataVanger.Core;

namespace DataVanger.Infrastructure;

/// <summary>
/// Performance cache for signature verification results, mirroring
/// <see cref="Sha256HashService"/>. Signature verification (embedded WinVerifyTrust +
/// the expensive catalog probe) is memoized by <c>(path, last-write, length)</c> and a
/// trust-environment <c>fingerprint</c> (which changes when the OS catalog store changes),
/// so unchanged files are not re-verified — making repeat scans fast.
///
/// Caching ONLY stores raw verification facts (signed?, signer subject, source,
/// present-but-invalid); it never decides trust. Any file change (mtime/size) or
/// fingerprint change is a miss, so it can never grant stale trust.
/// </summary>
internal sealed class SignatureTrustCache
{
    private readonly string _cachePath;
    private ConcurrentDictionary<string, TrustCacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    public SignatureTrustCache(string cachePath)
    {
        _cachePath = cachePath;
        Load();
    }

    public bool TryGet(FileInfo file, string fingerprint, out SignatureVerificationResult result)
    {
        result = SignatureVerificationResult.Unsigned;
        if (file is null) return false;
        try
        {
            if (_cache.TryGetValue(file.FullName, out var e)
                && e.LastWriteUtcTicks == file.LastWriteTimeUtc.Ticks
                && e.Length == file.Length
                && string.Equals(e.Fingerprint, fingerprint, StringComparison.Ordinal))
            {
                result = new SignatureVerificationResult
                {
                    IsSigned = e.IsSigned,
                    SignerSubject = e.SignerSubject ?? "",
                    Source = (SignatureSource)e.Source,
                    SignaturePresentButUnverified = e.PresentButUnverified,
                };
                return true;
            }
        }
        catch (Exception)
        {
            // Corrupt/unreadable entry - treat as a miss.
        }
        return false;
    }

    public void Store(FileInfo file, string fingerprint, SignatureVerificationResult r)
    {
        if (file is null || r is null) return;
        try
        {
            _cache[file.FullName] = new TrustCacheEntry
            {
                Path = file.FullName,
                LastWriteUtcTicks = file.LastWriteTimeUtc.Ticks,
                Length = file.Length,
                Fingerprint = fingerprint,
                IsSigned = r.IsSigned,
                SignerSubject = r.SignerSubject,
                Source = (int)r.Source,
                PresentButUnverified = r.SignaturePresentButUnverified,
                LastSeen = DateTime.Now,
            };
        }
        catch (Exception)
        {
            // Never let cache bookkeeping break a scan.
        }
    }

    public void Persist()
    {
        try
        {
            var pruned = _cache.Values
                .Where(x => { try { return File.Exists(x.Path); } catch (Exception) { return false; } })
                .OrderByDescending(x => x.LastSeen)
                .Take(250_000)
                .ToList();
            var opts = new JsonSerializerOptions { WriteIndented = false };
            File.WriteAllText(_cachePath, JsonSerializer.Serialize(pruned, opts), Encoding.UTF8);
        }
        catch (Exception)
        {
            // Never let cache persistence crash a scan.
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_cachePath)) return;
            var list = JsonSerializer.Deserialize<List<TrustCacheEntry>>(File.ReadAllText(_cachePath));
            if (list != null)
            {
                _cache = new ConcurrentDictionary<string, TrustCacheEntry>(
                    list.Where(x => !string.IsNullOrWhiteSpace(x.Path))
                        .GroupBy(x => x.Path, StringComparer.OrdinalIgnoreCase)
                        .Select(g => g.OrderByDescending(x => x.LastSeen).First())
                        .ToDictionary(x => x.Path, x => x, StringComparer.OrdinalIgnoreCase),
                    StringComparer.OrdinalIgnoreCase);
            }
        }
        catch (Exception)
        {
            _cache = new ConcurrentDictionary<string, TrustCacheEntry>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public sealed class TrustCacheEntry
    {
        public string Path { get; set; } = "";
        public long LastWriteUtcTicks { get; set; }
        public long Length { get; set; }
        public string Fingerprint { get; set; } = "";
        public bool IsSigned { get; set; }
        public string SignerSubject { get; set; } = "";
        public int Source { get; set; }
        public bool PresentButUnverified { get; set; }
        public DateTime LastSeen { get; set; }
    }
}
