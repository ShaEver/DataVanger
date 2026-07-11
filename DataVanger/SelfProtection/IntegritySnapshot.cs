using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.SelfProtection;

/// <summary>
/// Immutable baseline of expected file hashes used by the integrity
/// validator.
///
/// Snapshots are deliberately simple: a path → SHA256 mapping the caller
/// builds at install/update time. The validator compares the current
/// disk content against this baseline and reports differences. The
/// snapshot itself does not authorise anything — it is data.
/// </summary>
public sealed class IntegritySnapshot
{
    private readonly Dictionary<string, string> _hashes;

    public IntegritySnapshot(IEnumerable<KeyValuePair<string, string>> entries)
    {
        if (entries is null) throw new ArgumentNullException(nameof(entries));
        _hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in entries)
        {
            if (string.IsNullOrWhiteSpace(kv.Key) || string.IsNullOrWhiteSpace(kv.Value)) continue;
            _hashes[kv.Key.Trim()] = kv.Value.Trim();
        }
    }

    public int Count => _hashes.Count;

    public IReadOnlyCollection<string> Paths => _hashes.Keys.ToArray();

    public bool TryGetHash(string path, out string hash)
    {
        if (string.IsNullOrWhiteSpace(path)) { hash = ""; return false; }
        return _hashes.TryGetValue(path, out hash!);
    }

    public static IntegritySnapshot Empty { get; } =
        new IntegritySnapshot(Array.Empty<KeyValuePair<string, string>>());
}
