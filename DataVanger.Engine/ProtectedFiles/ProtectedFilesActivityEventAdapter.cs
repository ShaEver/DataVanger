using System;
using System.Collections.Generic;
using System.Globalization;
using DataVanger.Shared.ProtectedFiles;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Maps normalized <see cref="RuntimeSecurityEvent"/>s into
/// <see cref="ProtectedFileObservation"/>s for the Protected Files
/// Activity Monitor (Phase 2 / Step 07).
///
/// The adapter only translates and enriches. It performs NO
/// classification: it never decides malware, never quarantines, never
/// kills a process, never reads file contents. Recovery indicators are
/// read as pre-normalized metadata LABELS only — the adapter never parses
/// or reconstructs OS commands.
/// </summary>
public sealed class ProtectedFilesActivityEventAdapter
{
    // Metadata key conventions (mirrors the ETW mapper's image/cmdline keys).
    public const string MetaImagePath    = "etw.image_path";
    public const string MetaPreviousPath = "protectedfiles.previous_path";
    public const string MetaByteCount    = "protectedfiles.bytes";
    public const string MetaEntropyAfter = "protectedfiles.entropy_after";
    public const string MetaEntropyBefore = "protectedfiles.entropy_before";

    private readonly bool _enableRecoveryIndicators;

    public ProtectedFilesActivityEventAdapter(bool enableRecoveryIndicators = true)
    {
        _enableRecoveryIndicators = enableRecoveryIndicators;
    }

    /// <summary>
    /// Maps a runtime event to a file-activity observation, or returns
    /// null when the event is not relevant to protected-file monitoring.
    /// Never throws.
    /// </summary>
    public ProtectedFileObservation? Map(RuntimeSecurityEvent runtimeEvent)
    {
        if (runtimeEvent is null) return null;

        var metadata = runtimeEvent.Metadata;

        // Recovery indicator labels can ride on any event (commonly a
        // TamperObserved or CommandLineObserved event already normalized
        // upstream). Labels only — never parsed commands.
        IReadOnlyList<string> recovery = Array.Empty<string>();
        if (_enableRecoveryIndicators)
        {
            recovery = RecoveryProtectionIndicators.Extract(metadata);
        }

        var kind = MapKind(runtimeEvent.Category);

        if (kind == ProtectedFileObservationKind.Unknown)
        {
            // Not a file event — but if it carries recovery labels, surface
            // a RecoveryIndicator observation so the monitor can correlate
            // it with the responsible process.
            if (recovery.Count > 0)
            {
                return BuildObservation(runtimeEvent, ProtectedFileObservationKind.RecoveryIndicator, metadata, recovery);
            }
            return null;
        }

        return BuildObservation(runtimeEvent, kind, metadata, recovery);
    }

    private static ProtectedFileObservation BuildObservation(
        RuntimeSecurityEvent runtimeEvent,
        ProtectedFileObservationKind kind,
        IReadOnlyDictionary<string, string> metadata,
        IReadOnlyList<string> recovery)
    {
        string? imagePath = null;
        string? previousPath = null;
        long? byteCount = null;
        double? entropyAfter = null;
        double? entropyBefore = null;

        if (metadata is { Count: > 0 })
        {
            if (metadata.TryGetValue(MetaImagePath, out var ip) && !string.IsNullOrEmpty(ip)) imagePath = ip;
            if (metadata.TryGetValue(MetaPreviousPath, out var pp) && !string.IsNullOrEmpty(pp)) previousPath = pp;
            if (metadata.TryGetValue(MetaByteCount, out var bc) &&
                long.TryParse(bc, NumberStyles.Integer, CultureInfo.InvariantCulture, out var b)) byteCount = b;
            if (metadata.TryGetValue(MetaEntropyAfter, out var ea) &&
                double.TryParse(ea, NumberStyles.Float, CultureInfo.InvariantCulture, out var dea)) entropyAfter = dea;
            if (metadata.TryGetValue(MetaEntropyBefore, out var eb) &&
                double.TryParse(eb, NumberStyles.Float, CultureInfo.InvariantCulture, out var deb)) entropyBefore = deb;
        }

        return new ProtectedFileObservation
        {
            Kind = kind,
            TimestampUtc = runtimeEvent.TimestampUtc == default ? DateTimeOffset.UtcNow : runtimeEvent.TimestampUtc,
            SourceEventId = runtimeEvent.EventId,
            ProcessId = runtimeEvent.ProcessId,
            ProcessName = runtimeEvent.ProcessName,
            ProcessImagePath = imagePath,
            ParentProcessId = runtimeEvent.ParentProcessId,
            ParentProcessName = runtimeEvent.ParentProcessName,
            SubjectPath = runtimeEvent.SubjectPath,
            PreviousPath = previousPath,
            ByteCount = byteCount,
            EntropyAfter = entropyAfter,
            EntropyBefore = entropyBefore,
            RecoveryIndicators = recovery,
        };
    }

    private static ProtectedFileObservationKind MapKind(RuntimeEventCategory category) => category switch
    {
        RuntimeEventCategory.FileCreated => ProtectedFileObservationKind.FileCreated,
        RuntimeEventCategory.FileChanged => ProtectedFileObservationKind.FileModified,
        RuntimeEventCategory.FileRenamed => ProtectedFileObservationKind.FileRenamed,
        RuntimeEventCategory.FileDeleted => ProtectedFileObservationKind.FileDeleted,
        _ => ProtectedFileObservationKind.Unknown,
    };
}
