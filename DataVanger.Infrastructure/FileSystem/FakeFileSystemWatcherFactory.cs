using System.Collections.Concurrent;
using System.Collections.Generic;
using DataVanger.Infrastructure.Runtime;
using DataVanger.Shared.Realtime;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Test factory that records every watcher it creates so tests can
/// access the underlying <see cref="FakeFileSystemWatcherAdapter"/>
/// and drive deterministic events through it.
/// </summary>
public sealed class FakeFileSystemWatcherFactory : IFileSystemWatcherFactory
{
    private readonly IRuntimeClock _clock;
    private readonly ConcurrentDictionary<string, FakeFileSystemWatcherAdapter> _byProfile = new();

    public FakeFileSystemWatcherFactory(IRuntimeClock? clock = null)
    {
        _clock = clock ?? new FakeRuntimeClock();
    }

    /// <summary>
    /// Names of profiles for which Create should immediately return a
    /// watcher whose <c>Start</c> reports failure (graceful degradation
    /// path used by tests).
    /// </summary>
    public HashSet<string> ProfilesThatFailOnStart { get; } = new();

    public IReadOnlyDictionary<string, FakeFileSystemWatcherAdapter> Watchers => _byProfile;

    public FakeFileSystemWatcherAdapter? Get(string profileName)
        => _byProfile.TryGetValue(profileName, out var w) ? w : null;

    public IFileSystemWatcherAdapter Create(RealtimeWatchProfile profile)
    {
        var watcher = new FakeFileSystemWatcherAdapter(profile, _clock);
        if (ProfilesThatFailOnStart.Contains(profile.Name))
        {
            watcher.FailOnStart = true;
            watcher.FailOnStartReason = "Synthetic failure injected by FakeFileSystemWatcherFactory.";
        }
        _byProfile[profile.Name] = watcher;
        return watcher;
    }
}
