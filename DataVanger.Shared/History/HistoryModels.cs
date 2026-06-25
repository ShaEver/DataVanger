using System;

namespace DataVanger.Shared.History;

/// <summary>The kind of event recorded in the persistent threat/action history.</summary>
public enum HistoryEventKind
{
    Scan = 0,
    Detection,
    RemediationAction,
    Verification,
    Rollback,
    Update,
    ServiceEvent,
}

/// <summary>
/// Honest outcome of a history event. <see cref="Pending"/> and
/// <see cref="RequiresReboot"/> deliberately do NOT mean success; a remediation is
/// only treated as resolved once a <see cref="HistoryEventKind.Verification"/> event
/// confirms it (see <see cref="HistoryStore.IsRemediationVerified"/>).
/// </summary>
public enum HistoryOutcome
{
    Info = 0,
    Pending,
    Succeeded,
    Failed,
    RequiresReboot,
    Verified,
    RolledBack,
}

/// <summary>
/// One durable history record. Data-only; created via the static factories so a
/// remediation can never be constructed as "already verified" — verification is a
/// separate, later event.
/// </summary>
public sealed record HistoryEvent
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;
    public HistoryEventKind Kind { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public string CorrelationId { get; init; } = string.Empty;
    public HistoryOutcome Outcome { get; init; } = HistoryOutcome.Info;

    public static HistoryEvent Scan(string title, string detail = "")
        => new() { Kind = HistoryEventKind.Scan, Title = title, Detail = detail, Outcome = HistoryOutcome.Info };

    public static HistoryEvent Detection(string title, string correlationId, string detail = "")
        => new() { Kind = HistoryEventKind.Detection, Title = title, CorrelationId = correlationId, Detail = detail, Outcome = HistoryOutcome.Info };

    public static HistoryEvent Remediation(string title, string correlationId, HistoryOutcome outcome, string detail = "")
        => new() { Kind = HistoryEventKind.RemediationAction, Title = title, CorrelationId = correlationId, Detail = detail, Outcome = outcome };

    public static HistoryEvent Verification(string title, string correlationId, bool passed, string detail = "")
        => new()
        {
            Kind = HistoryEventKind.Verification,
            Title = title,
            CorrelationId = correlationId,
            Detail = detail,
            Outcome = passed ? HistoryOutcome.Verified : HistoryOutcome.Failed,
        };

    public static HistoryEvent Rollback(string title, string correlationId, string detail = "")
        => new() { Kind = HistoryEventKind.Rollback, Title = title, CorrelationId = correlationId, Detail = detail, Outcome = HistoryOutcome.RolledBack };

    public static HistoryEvent Update(string title, HistoryOutcome outcome, string detail = "")
        => new() { Kind = HistoryEventKind.Update, Title = title, Detail = detail, Outcome = outcome };

    public static HistoryEvent Service(string title, HistoryOutcome outcome, string detail = "")
        => new() { Kind = HistoryEventKind.ServiceEvent, Title = title, Detail = detail, Outcome = outcome };
}
