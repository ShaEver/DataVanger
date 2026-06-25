namespace DataVanger.Shared.Service;

/// <summary>
/// Lifecycle states for the DataVanger service runtime introduced in
/// Phase 2 Step 02 (Windows Service Host).
/// </summary>
public enum DataVangerServiceState
{
    NotStarted = 0,
    Starting = 1,
    Running = 2,
    Degraded = 3,
    Stopping = 4,
    Stopped = 5,
    Failed = 6,
}
