using DataVanger.Infrastructure.Runtime;
using DataVanger.Shared.Realtime;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Default factory that produces real <see cref="FileSystemWatcherAdapter"/>
/// instances. Tests must use <c>FakeFileSystemWatcherFactory</c> instead
/// so they never touch a real disk and never depend on FS notifications.
/// </summary>
public sealed class FileSystemWatcherFactory : IFileSystemWatcherFactory
{
    private readonly IRuntimeClock _clock;

    public FileSystemWatcherFactory(IRuntimeClock? clock = null)
    {
        _clock = clock ?? SystemRuntimeClock.Instance;
    }

    public IFileSystemWatcherAdapter Create(RealtimeWatchProfile profile)
        => new FileSystemWatcherAdapter(profile, _clock);
}
