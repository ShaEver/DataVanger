using System;
using System.Collections.Generic;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Bounded aggregate of file-mutation activity for a single tracked
/// correlation key (process) in the Protected Files Activity Monitor
/// (Phase 2 / Step 07).
///
/// Bounded by design:
///   - distinct directories are capped at <c>maxDirectories</c>;
///   - distinct extension transitions are capped at <c>maxTransitions</c>;
///   - the profile NEVER stores file contents, only counts/labels.
/// </summary>
public sealed class FileMutationProfile
{
    private readonly int _maxDirectories;
    private readonly int _maxTransitions;

    private readonly HashSet<string> _directories = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _extensionTransitions = new(StringComparer.OrdinalIgnoreCase);

    public FileMutationProfile(int maxDirectories, int maxTransitions)
    {
        _maxDirectories = maxDirectories < 1 ? 256 : maxDirectories;
        _maxTransitions = maxTransitions < 1 ? 128 : maxTransitions;
    }

    public long CreatedCount { get; private set; }
    public long ModifiedCount { get; private set; }
    public long RenamedCount { get; private set; }
    public long DeletedCount { get; private set; }

    /// <summary>Count of renames whose extension transition was suspicious.</summary>
    public long SuspiciousTransitionCount { get; private set; }

    /// <summary>Advisory total of reported mutation bytes (bounded, never file contents).</summary>
    public long TotalBytes { get; private set; }

    /// <summary>Whether a high-entropy (after) reading was observed (weak signal).</summary>
    public bool ObservedHighEntropy { get; private set; }

    /// <summary>Whether a suspicious entropy increase (before→after) was observed (weak signal).</summary>
    public bool ObservedEntropyIncrease { get; private set; }

    public int DistinctDirectoryCount => _directories.Count;

    public IReadOnlyDictionary<string, int> ExtensionTransitions => _extensionTransitions;

    public void RecordCreated() => CreatedCount++;
    public void RecordModified() => ModifiedCount++;
    public void RecordDeleted() => DeletedCount++;
    public void RecordRenamed() => RenamedCount++;

    public void RecordBytes(long? bytes)
    {
        if (bytes is long b && b > 0)
        {
            // Saturate rather than overflow.
            TotalBytes = b > long.MaxValue - TotalBytes ? long.MaxValue : TotalBytes + b;
        }
    }

    public void RecordEntropy(bool highEntropy, bool suspiciousIncrease)
    {
        if (highEntropy) ObservedHighEntropy = true;
        if (suspiciousIncrease) ObservedEntropyIncrease = true;
    }

    /// <summary>Adds a directory to the bounded distinct-directory set.</summary>
    public void RecordDirectory(string? directory)
    {
        if (string.IsNullOrEmpty(directory)) return;
        if (_directories.Count >= _maxDirectories && !_directories.Contains(directory)) return;
        _directories.Add(directory);
    }

    /// <summary>Records a (possibly suspicious) extension transition into the bounded map.</summary>
    public void RecordTransition(string transitionKey, bool suspicious)
    {
        if (string.IsNullOrEmpty(transitionKey)) return;
        if (suspicious) SuspiciousTransitionCount++;

        if (_extensionTransitions.TryGetValue(transitionKey, out var count))
        {
            _extensionTransitions[transitionKey] = count + 1;
        }
        else if (_extensionTransitions.Count < _maxTransitions)
        {
            _extensionTransitions[transitionKey] = 1;
        }
    }

    /// <summary>Returns the top-N transitions by count (descending), bounded.</summary>
    public IReadOnlyList<string> TopTransitions(int n)
    {
        if (_extensionTransitions.Count == 0 || n <= 0) return Array.Empty<string>();
        var list = new List<KeyValuePair<string, int>>(_extensionTransitions);
        list.Sort((a, b) => b.Value.CompareTo(a.Value));
        var result = new List<string>(Math.Min(n, list.Count));
        for (int i = 0; i < list.Count && i < n; i++)
        {
            result.Add($"{list[i].Key} (x{list[i].Value})");
        }
        return result;
    }
}
