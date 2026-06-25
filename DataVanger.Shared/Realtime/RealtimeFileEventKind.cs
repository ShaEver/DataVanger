namespace DataVanger.Shared.Realtime;

/// <summary>
/// Kinds of file system events normalized by the real-time protection
/// pipeline. Watcher lifecycle and error notifications are modelled as
/// events too so they can flow through the same status pipeline without
/// special-casing.
/// </summary>
public enum RealtimeFileEventKind
{
    Created,
    Changed,
    Renamed,
    Deleted,
    ExistingFileDiscovered,
    WatcherError,
    WatcherStarted,
    WatcherStopped
}
