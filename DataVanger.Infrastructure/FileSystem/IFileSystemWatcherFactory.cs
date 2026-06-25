using DataVanger.Shared.Realtime;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Factory abstraction so the orchestrator can swap in fake watchers
/// for deterministic tests without touching real disks or admin
/// privileges.
/// </summary>
public interface IFileSystemWatcherFactory
{
    IFileSystemWatcherAdapter Create(RealtimeWatchProfile profile);
}
