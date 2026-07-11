using System;
using System.Collections.Generic;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Shared.Ipc;
using DataVanger.Shared.Quarantine;
using DataVanger.Shared.Service;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Dependencies and shared in-memory state available to the IPC command
/// handlers. Every dependency is optional: a null dependency means the
/// corresponding command degrades to a structured, honest "unsupported" or
/// "unavailable" response rather than failing. This keeps the router fully
/// testable without a real installed service, quarantine store, or update feed.
/// </summary>
public sealed class DataVangerServiceCommandContext
{
    /// <summary>Authoritative runtime status source. Null => status unavailable.</summary>
    public IDataVangerServiceRuntime? Runtime { get; init; }

    /// <summary>Secure Quarantine V2 service. Null => quarantine commands unsupported.</summary>
    public IQuarantineService? Quarantine { get; init; }

    /// <summary>Gate used by remediation IPC before any execution is attempted.</summary>
    public RemediationExecutionGate RemediationGate { get; init; } = new();

    /// <summary>
    /// Service-authoritative remediation contexts and consent tokens. The IPC
    /// handler must resolve requests here before it can authorize execution.
    /// </summary>
    public RemediationServerContextStore RemediationContexts { get; init; } = new();

    /// <summary>Authorized remediation executor. Null => remediation execution unsupported.</summary>
    public IRemediationPlanExecutor? RemediationExecutor { get; init; }

    /// <summary>Clock used for consent expiry validation at the IPC boundary.</summary>
    public Func<DateTimeOffset> RemediationNowUtc { get; init; } = () => DateTimeOffset.UtcNow;

    /// <summary>Provides an honest update status snapshot. Null => disabled.</summary>
    public Func<UpdateStatusDto>? UpdateStatusProvider { get; init; }

    /// <summary>Provides bounded recent events (already DTO-projected). Null => none.</summary>
    public Func<IReadOnlyList<SecurityEventDto>>? RecentEventsProvider { get; init; }

    /// <summary>Short, non-sensitive configuration summary lines. Null => minimal.</summary>
    public IReadOnlyList<string>? ConfigurationSummaryLines { get; init; }

    /// <summary>
    /// Host kind label: "Service" for a production host, otherwise a
    /// development / test host. Drives <see cref="DataVangerCommandType.ShutdownDevelopmentHost"/>.
    /// </summary>
    public string HostKind { get; init; } = "DevelopmentHost";

    /// <summary>
    /// Invoked only when an allowed <see cref="DataVangerCommandType.ShutdownDevelopmentHost"/>
    /// is accepted on a development/test host. Never invoked for a production
    /// service host.
    /// </summary>
    public Action? DevelopmentHostShutdownCallback { get; init; }

    /// <summary>True for any non-production host. A production service refuses dev shutdown.</summary>
    public bool IsProductionServiceHost =>
        HostKind.Equals("Service", StringComparison.OrdinalIgnoreCase);

    public ScanOperationRegistry Scans { get; } = new();

    public ProtectionControlState Protection { get; } = new();
}
