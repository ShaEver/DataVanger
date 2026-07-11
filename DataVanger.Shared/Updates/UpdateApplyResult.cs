namespace DataVanger.Shared.Updates;

/// <summary>
/// Structured result of an apply/rollback operation. Failures are returned as
/// values here — the service does not surface unhandled exceptions for normal
/// update problems.
///
/// Anti-FP guarantee: <see cref="IsConfirmedMalware"/> is a hard-coded
/// constant <c>false</c>.
/// </summary>
public sealed class UpdateApplyResult
{
    public bool Succeeded { get; init; }

    public UpdateResultKind Kind { get; init; } = UpdateResultKind.None;

    public string Message { get; init; } = string.Empty;

    public string FeedId { get; init; } = string.Empty;

    public long Sequence { get; init; }

    public UpdateStateSnapshot State { get; init; } = UpdateStateSnapshot.Empty(string.Empty);

    /// <summary>Always false. Update activity is never a malware verdict.</summary>
    public bool IsConfirmedMalware => false;

    public static UpdateApplyResult Success(UpdateResultKind kind, string feedId, long sequence, UpdateStateSnapshot state, string message = "")
        => new()
        {
            Succeeded = true,
            Kind = kind,
            Message = message,
            FeedId = feedId,
            Sequence = sequence,
            State = state,
        };

    public static UpdateApplyResult Failure(UpdateResultKind kind, string message, string feedId, UpdateStateSnapshot state, long sequence = 0)
        => new()
        {
            Succeeded = false,
            Kind = kind,
            Message = message,
            FeedId = feedId,
            Sequence = sequence,
            State = state,
        };
}
