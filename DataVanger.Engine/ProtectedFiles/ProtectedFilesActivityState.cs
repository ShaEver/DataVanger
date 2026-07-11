using System;
using System.Collections.Generic;
using DataVanger.Shared.ProtectedFiles;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Short-lived, bounded correlation state for a single tracked process in
/// the Protected Files Activity Monitor (Phase 2 / Step 07).
///
/// Holds the sliding activity windows, the bounded mutation profile, the
/// set of protected folder roots touched, and the normalized recovery
/// indicator labels observed for one process. It NEVER stores file
/// contents.
/// </summary>
public sealed class ProtectedFilesActivityState
{
    private readonly HashSet<string> _protectedFolderRoots = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _recoveryIndicators = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _maxProtectedRoots;

    public ProtectedFilesActivityState(
        string correlationKey,
        TimeSpan window,
        int maxWindowSamples,
        int maxDirectories,
        int maxTransitions,
        DateTimeOffset nowUtc)
    {
        CorrelationKey = correlationKey;
        FirstSeenUtc = nowUtc;
        LastSeenUtc = nowUtc;
        _maxProtectedRoots = maxDirectories < 1 ? 256 : maxDirectories;

        ModificationWindow = new ActivityWindow(window, maxWindowSamples);
        RenameWindow = new ActivityWindow(window, maxWindowSamples);
        DeleteWindow = new ActivityWindow(window, maxWindowSamples);
        MutationProfile = new FileMutationProfile(maxDirectories, maxTransitions);
    }

    public string CorrelationKey { get; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessImagePath { get; set; }

    public DateTimeOffset FirstSeenUtc { get; }
    public DateTimeOffset LastSeenUtc { get; set; }

    public ActivityWindow ModificationWindow { get; }
    public ActivityWindow RenameWindow { get; }
    public ActivityWindow DeleteWindow { get; }
    public FileMutationProfile MutationProfile { get; }

    /// <summary>The highest severity already emitted for this key (escalation-only de-dup).</summary>
    public ProtectedFilesActivitySeverity HighestEmittedSeverity { get; set; }
        = ProtectedFilesActivitySeverity.Informational;

    public IReadOnlyCollection<string> ProtectedFolderRoots => _protectedFolderRoots;
    public IReadOnlyCollection<string> RecoveryIndicators => _recoveryIndicators;

    public bool HasRecoveryIndicators => _recoveryIndicators.Count > 0;
    public bool HasProtectedActivity => _protectedFolderRoots.Count > 0;

    /// <summary>A representative protected folder root (first observed), for evidence summaries.</summary>
    public string? PrimaryProtectedFolderRoot { get; private set; }

    public void TouchProtectedFolder(string? root)
    {
        if (string.IsNullOrEmpty(root)) return;
        PrimaryProtectedFolderRoot ??= root;
        if (_protectedFolderRoots.Count >= _maxProtectedRoots && !_protectedFolderRoots.Contains(root!)) return;
        _protectedFolderRoots.Add(root!);
    }

    public void AddRecoveryIndicators(IReadOnlyList<string> labels)
    {
        if (labels is null) return;
        foreach (var label in labels)
        {
            if (string.IsNullOrWhiteSpace(label)) continue;
            // Bounded: there are only a handful of known labels.
            if (_recoveryIndicators.Count >= 32 && !_recoveryIndicators.Contains(label)) continue;
            _recoveryIndicators.Add(label);
        }
    }
}
