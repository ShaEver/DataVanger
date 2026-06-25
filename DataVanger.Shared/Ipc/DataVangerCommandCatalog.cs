using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Broad routing category for a <see cref="DataVangerCommandType"/>. Used by
/// the service-side router to map a command onto the correct handler and by
/// the UI to group controls. Categories are NOT classification verdicts.
/// </summary>
public enum DataVangerCommandCategory
{
    Unknown = 0,
    Status,
    Configuration,
    ProtectionControl,
    Scan,
    Quarantine,
    Remediation,
    Update,
    EventQuery,
    Diagnostics,
}

/// <summary>
/// The command allowlist. The catalog is the single source of truth for
/// "which commands exist" and "which category each command belongs to".
///
/// Any command type not present here (including <see cref="DataVangerCommandType.Unknown"/>)
/// MUST be rejected by the router with a structured error — never executed.
/// </summary>
public static class DataVangerCommandCatalog
{
    private static readonly IReadOnlyDictionary<DataVangerCommandType, DataVangerCommandCategory> Map =
        new Dictionary<DataVangerCommandType, DataVangerCommandCategory>
        {
            [DataVangerCommandType.GetServiceStatus] = DataVangerCommandCategory.Status,
            [DataVangerCommandType.GetModuleStatus] = DataVangerCommandCategory.Status,
            [DataVangerCommandType.GetProtectionStatus] = DataVangerCommandCategory.Status,
            [DataVangerCommandType.GetRecentEvents] = DataVangerCommandCategory.EventQuery,
            [DataVangerCommandType.GetConfigurationSummary] = DataVangerCommandCategory.Configuration,

            [DataVangerCommandType.PauseRealtimeProtection] = DataVangerCommandCategory.ProtectionControl,
            [DataVangerCommandType.ResumeRealtimeProtection] = DataVangerCommandCategory.ProtectionControl,

            [DataVangerCommandType.StartQuickScan] = DataVangerCommandCategory.Scan,
            [DataVangerCommandType.StartCustomScan] = DataVangerCommandCategory.Scan,
            [DataVangerCommandType.CancelScan] = DataVangerCommandCategory.Scan,
            [DataVangerCommandType.GetScanStatus] = DataVangerCommandCategory.Scan,

            [DataVangerCommandType.ListQuarantineItems] = DataVangerCommandCategory.Quarantine,
            [DataVangerCommandType.GetQuarantineItemDetails] = DataVangerCommandCategory.Quarantine,
            [DataVangerCommandType.RestoreQuarantineItem] = DataVangerCommandCategory.Quarantine,
            [DataVangerCommandType.DeleteQuarantineItem] = DataVangerCommandCategory.Quarantine,

            [DataVangerCommandType.ExecuteRemediationAction] = DataVangerCommandCategory.Remediation,

            [DataVangerCommandType.CheckForUpdates] = DataVangerCommandCategory.Update,
            [DataVangerCommandType.GetUpdateStatus] = DataVangerCommandCategory.Update,

            [DataVangerCommandType.ExportDiagnosticBundle] = DataVangerCommandCategory.Diagnostics,
            [DataVangerCommandType.Ping] = DataVangerCommandCategory.Diagnostics,
            [DataVangerCommandType.ShutdownDevelopmentHost] = DataVangerCommandCategory.Diagnostics,
        };

    /// <summary>True when the command is on the allowlist.</summary>
    public static bool IsAllowed(DataVangerCommandType commandType)
        => commandType != DataVangerCommandType.Unknown && Map.ContainsKey(commandType);

    /// <summary>
    /// Returns the category for an allowed command, or
    /// <see cref="DataVangerCommandCategory.Unknown"/> for a command that is
    /// not on the allowlist.
    /// </summary>
    public static DataVangerCommandCategory CategoryOf(DataVangerCommandType commandType)
        => Map.TryGetValue(commandType, out var category) ? category : DataVangerCommandCategory.Unknown;

    /// <summary>Snapshot of every allowed command type.</summary>
    public static IReadOnlyCollection<DataVangerCommandType> AllowedCommands => (IReadOnlyCollection<DataVangerCommandType>)Map.Keys;
}
