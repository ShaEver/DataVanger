using System.Collections.Generic;
using DataVanger.Shared.RuntimeEvents;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Builds <see cref="RuntimeSecurityEvent"/>s for update activity.
///
/// Anti-FP guarantee: every event is operational telemetry —
///   Source   = <see cref="RuntimeEventSource.UpdateManager"/>
///   Category = <see cref="RuntimeEventCategory.UpdateAction"/>
/// An update event NEVER classifies anything as ConfirmedMalware, never
/// quarantines, never kills, and never blocks. Severity tops out at
/// <see cref="RuntimeEventSeverity.High"/> for failures/rejections — never
/// "Critical" — to underline that updates are not verdicts.
/// </summary>
public static class UpdateEventFactory
{
    public static RuntimeSecurityEvent Create(
        UpdateResultKind kind,
        string feedId,
        long sequence,
        string title,
        string description,
        RuntimeEventSeverity severity)
    {
        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.UpdateManager,
            Category = RuntimeEventCategory.UpdateAction,
            Severity = severity,
            Title = title,
            Description = description,
            SubjectPath = null,
            Metadata = new Dictionary<string, string>
            {
                ["feedId"] = feedId ?? string.Empty,
                ["sequence"] = sequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["resultKind"] = kind.ToString(),
            },
        };
    }

    /// <summary>Maps a result kind to a telemetry severity (never Critical).</summary>
    public static RuntimeEventSeverity SeverityFor(UpdateResultKind kind) => kind switch
    {
        UpdateResultKind.Accepted => RuntimeEventSeverity.Informational,
        UpdateResultKind.Applied => RuntimeEventSeverity.Informational,
        UpdateResultKind.AlreadyCurrent => RuntimeEventSeverity.Informational,
        UpdateResultKind.RollbackCompleted => RuntimeEventSeverity.Medium,
        UpdateResultKind.NoRollbackAvailable => RuntimeEventSeverity.Medium,
        UpdateResultKind.DowngradeRejected => RuntimeEventSeverity.High,
        UpdateResultKind.SequenceConflict => RuntimeEventSeverity.High,
        UpdateResultKind.SignatureInvalid => RuntimeEventSeverity.High,
        UpdateResultKind.UnknownKey => RuntimeEventSeverity.High,
        UpdateResultKind.UnsupportedAlgorithm => RuntimeEventSeverity.High,
        UpdateResultKind.StagingFailed => RuntimeEventSeverity.High,
        UpdateResultKind.None => RuntimeEventSeverity.Informational,
        _ => RuntimeEventSeverity.Medium,
    };
}
