namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// Confidence the runtime binding has in a behavioral evidence item.
///
/// Confidence is descriptive only and has NO classification authority.
/// Even <see cref="High"/> confidence behavioral evidence can never, by
/// itself, become ConfirmedMalware.
/// </summary>
public enum BehavioralRuntimeConfidence
{
    Low = 0,
    Medium,
    High,
}
