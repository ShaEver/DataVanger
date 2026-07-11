using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Service;

/// <summary>
/// Immutable status snapshot exposed by the service runtime. Designed to
/// be consumed later by UI / IPC / diagnostics without creating any
/// coupling on internal runtime state.
/// </summary>
public sealed class DataVangerServiceStatus
{
    public DataVangerServiceStatus(
        DataVangerServiceState state,
        DataVangerRuntimeMode mode,
        DateTimeOffset lastUpdatedUtc,
        DateTimeOffset? startedAtUtc,
        IReadOnlyList<string> warnings,
        IReadOnlyList<DataVangerRuntimeModuleStatus> modules)
    {
        State = state;
        Mode = mode;
        LastUpdatedUtc = lastUpdatedUtc;
        StartedAtUtc = startedAtUtc;
        Warnings = warnings ?? Array.Empty<string>();
        Modules = modules ?? Array.Empty<DataVangerRuntimeModuleStatus>();
    }

    public DataVangerServiceState State { get; }

    public DataVangerRuntimeMode Mode { get; }

    public DateTimeOffset LastUpdatedUtc { get; }

    public DateTimeOffset? StartedAtUtc { get; }

    public bool IsDevelopmentMode => Mode == DataVangerRuntimeMode.Development;

    public bool IsServiceMode => Mode == DataVangerRuntimeMode.Service;

    public IReadOnlyList<string> Warnings { get; }

    public IReadOnlyList<DataVangerRuntimeModuleStatus> Modules { get; }

    /// <summary>
    /// True only when at least one registered module is Available AND the
    /// runtime is in Running state. Phase 2 Step 02 ships with all modules
    /// passive / not-implemented, so this must be false until later phases
    /// promote a module to Available.
    /// </summary>
    public bool HasActiveProtection
    {
        get
        {
            if (State != DataVangerServiceState.Running) return false;
            for (int i = 0; i < Modules.Count; i++)
            {
                if (Modules[i].IsActiveProtection) return true;
            }
            return false;
        }
    }
}
