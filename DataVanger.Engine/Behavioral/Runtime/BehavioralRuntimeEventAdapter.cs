using System;
using System.Collections.Generic;
using DataVanger.Shared.Behavioral.Runtime;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.Behavioral.Runtime;

/// <summary>
/// Maps normalized <see cref="RuntimeSecurityEvent"/>s into
/// <see cref="BehavioralRuntimeObservation"/>s (Phase 2 / Step 06).
///
/// The adapter only translates and enriches. It performs NO
/// classification: it never decides malware, never quarantines, never
/// kills a process. Indicator tags it attaches are descriptive only.
///
/// Metadata keys mirror those written by
/// <c>DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper</c> so that an
/// ETW-sourced event and a hand-built test event are read identically.
/// The constants are duplicated here (not referenced) to avoid a hard
/// dependency from DataVanger.Engine onto DataVanger.Infrastructure.
/// </summary>
public sealed class BehavioralRuntimeEventAdapter
{
    public const string MetaImagePath       = "etw.image_path";
    public const string MetaCommandLine     = "etw.command_line";
    public const string MetaIndicatorPrefix = "etw.indicator.";

    private readonly bool _enablePowerShellIndicators;

    public BehavioralRuntimeEventAdapter(bool enablePowerShellIndicators = true)
    {
        _enablePowerShellIndicators = enablePowerShellIndicators;
    }

    /// <summary>
    /// Maps a runtime event to an observation, or returns null when the
    /// event is not behaviorally relevant. Never throws.
    /// </summary>
    public BehavioralRuntimeObservation? Map(RuntimeSecurityEvent runtimeEvent)
    {
        if (runtimeEvent is null) return null;

        var kind = MapKind(runtimeEvent.Category);
        if (kind == BehavioralObservationKind.Unknown) return null;

        string? imagePath = runtimeEvent.SubjectPath;
        string? commandLine = null;
        var indicators = new List<string>();

        if (runtimeEvent.Metadata is { Count: > 0 })
        {
            foreach (var kvp in runtimeEvent.Metadata)
            {
                if (kvp.Key.Equals(MetaImagePath, StringComparison.Ordinal) && string.IsNullOrEmpty(imagePath))
                {
                    imagePath = kvp.Value;
                }
                else if (kvp.Key.Equals(MetaCommandLine, StringComparison.Ordinal))
                {
                    commandLine = kvp.Value;
                }
                else if (kvp.Key.StartsWith(MetaIndicatorPrefix, StringComparison.Ordinal))
                {
                    var tag = kvp.Key.Substring(MetaIndicatorPrefix.Length);
                    if (!string.IsNullOrEmpty(tag)) AddDistinct(indicators, tag);
                }
            }
        }

        // For file/persistence/tamper observations the SubjectPath is the
        // affected object, not the process image.
        if (kind is BehavioralObservationKind.FileActivity
                  or BehavioralObservationKind.Persistence
                  or BehavioralObservationKind.Tamper)
        {
            imagePath = null;
        }

        // Descriptive command-line enrichment (never a verdict).
        if (_enablePowerShellIndicators && !string.IsNullOrEmpty(commandLine))
        {
            foreach (var tag in BehavioralCommandLineIndicators.DetectPowerShellIndicators(runtimeEvent.ProcessName, commandLine))
            {
                AddDistinct(indicators, tag);
            }
        }

        return new BehavioralRuntimeObservation
        {
            Kind = kind,
            TimestampUtc = runtimeEvent.TimestampUtc,
            SourceEventId = runtimeEvent.EventId,
            ProcessId = runtimeEvent.ProcessId,
            ProcessName = runtimeEvent.ProcessName,
            ImagePath = imagePath,
            CommandLine = commandLine,
            ParentProcessId = runtimeEvent.ParentProcessId,
            ParentProcessName = runtimeEvent.ParentProcessName,
            SubjectPath = runtimeEvent.SubjectPath,
            Indicators = indicators,
        };
    }

    private static BehavioralObservationKind MapKind(RuntimeEventCategory category) => category switch
    {
        RuntimeEventCategory.ProcessCreated => BehavioralObservationKind.ProcessStart,
        RuntimeEventCategory.CommandLineObserved => BehavioralObservationKind.CommandLine,
        RuntimeEventCategory.ScriptObserved => BehavioralObservationKind.Script,
        RuntimeEventCategory.FileCreated => BehavioralObservationKind.FileActivity,
        RuntimeEventCategory.FileChanged => BehavioralObservationKind.FileActivity,
        RuntimeEventCategory.FileDeleted => BehavioralObservationKind.FileActivity,
        RuntimeEventCategory.FileRenamed => BehavioralObservationKind.FileActivity,
        RuntimeEventCategory.PersistenceObserved => BehavioralObservationKind.Persistence,
        RuntimeEventCategory.TamperObserved => BehavioralObservationKind.Tamper,
        _ => BehavioralObservationKind.Unknown,
    };

    private static void AddDistinct(List<string> list, string tag)
    {
        foreach (var existing in list)
        {
            if (existing.Equals(tag, StringComparison.OrdinalIgnoreCase)) return;
        }
        list.Add(tag);
    }
}
