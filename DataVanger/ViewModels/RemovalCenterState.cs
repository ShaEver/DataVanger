using DataVanger.Shared.Remediation;

namespace DataVanger.ViewModels;

/// <summary>
/// Lifecycle of the Removal Center consent/visualization surface. The Removal
/// Center never executes remediation in the WPF process; every transition past
/// <see cref="PlanReady"/> is driven by a service response received over IPC.
/// </summary>
public enum RemovalCenterState
{
    Empty = 0,
    PlanReady,
    AwaitingConfirmation,
    Executing,
    Succeeded,
    Failed,
    RebootRequired,
    VerificationNeeded,
}

/// <summary>
/// The threat plus the intended action the user chose to act on. It is sourced
/// from a server-side detection (correlation id + target); the WPF process never
/// invents the threat band or evidence — those stay server-authoritative and are
/// resolved by the service from the correlation id and target.
/// </summary>
public sealed record RemovalCenterThreatContext
{
    public required string CorrelationId { get; init; }
    public required RemediationIpcActionKind Action { get; init; }
    public required RemediationIpcTargetKind TargetKind { get; init; }
    public required string TargetIdentity { get; init; }
    public string Title { get; init; } = string.Empty;
    public string RiskText { get; init; } = string.Empty;
}

/// <summary>A single remediation step exactly as reported back by the service.</summary>
public sealed record RemovalCenterStepView(
    string Action,
    string Target,
    string Outcome,
    bool Succeeded,
    bool NoChange,
    string Reason);
