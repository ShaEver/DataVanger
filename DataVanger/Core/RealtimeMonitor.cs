using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DataVanger.Core;

public sealed class RealtimeMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _debounce = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _dangerExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".hta", ".msi", ".lnk", ".dll", ".sys", ".zip", ".jar" };

    public bool IsRunning => _watchers.Count > 0;
    public event Action<string>? SuspiciousFileCreated;

    public void Start()
    {
        Stop();
        foreach (var dir in GetMonitorTargets().Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                watcher.Created += OnChanged;
                watcher.Renamed += OnRenamed;
                _watchers.Add(watcher);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException
                                       and not StackOverflowException
                                       and not AccessViolationException
                                       and not System.Threading.ThreadAbortException)
            {
                // Watcher could not be registered for this directory - skip it and preserve the rest; fatal CLR exceptions are not swallowed.
            }
        }
    }

    public void Stop()
    {
        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Created -= OnChanged;
                watcher.Renamed -= OnRenamed;
                watcher.Dispose();
            }
            catch (Exception)
            {
                // Dispose/Stop may throw on already-disposed or never-started watchers - ignore and continue teardown.
            }
        }
        _watchers.Clear();
    }

    private void OnChanged(object sender, FileSystemEventArgs e) => Check(e.FullPath);
    private void OnRenamed(object sender, RenamedEventArgs e) => Check(e.FullPath);

    private void Check(string path)
    {
        try
        {
            if (!_dangerExt.Contains(Path.GetExtension(path))) return;
            var now = DateTime.UtcNow;
            _debounce[path] = now;
            _ = Task.Run(async () =>
            {
                await Task.Delay(900).ConfigureAwait(false);
                if (!_debounce.TryGetValue(path, out var stamp) || stamp != now) return;
                if (!await WaitUntilStableAsync(path).ConfigureAwait(false)) return;
                _debounce.TryRemove(path, out _);
                SuspiciousFileCreated?.Invoke(path);
            });
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed path or scheduling failure for a single event - drop it and keep monitoring; fatal CLR exceptions are not swallowed.
        }
    }

    private static async Task<bool> WaitUntilStableAsync(string path)
    {
        long last = -1;
        for (int i = 0; i < 8; i++)
        {
            try
            {
                if (!File.Exists(path)) return false;
                var fi = new FileInfo(path);
                if (fi.Length == last)
                {
                    using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    return true;
                }
                last = fi.Length;
            }
            catch (UnauthorizedAccessException)
            {
                // Protected file - retry on the next interval.
            }
            catch (IOException)
            {
                // File still locked/being written - retry on the next interval.
            }
            await Task.Delay(250).ConfigureAwait(false);
        }
        return File.Exists(path);
    }

    private static IEnumerable<string> GetMonitorTargets()
    {
        string up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string app = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string pdata = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        yield return Path.Combine(up, "Downloads");
        yield return Path.Combine(up, "Desktop");
        yield return Path.GetTempPath();
        yield return app;
        yield return Path.Combine(app, @"Microsoft\Windows\Start Menu\Programs\Startup");
        yield return Path.Combine(pdata, @"Microsoft\Windows\Start Menu\Programs\Startup");
        yield return local;
        yield return Path.Combine(local, @"Google\Chrome\User Data\Default\Extensions");
        yield return Path.Combine(local, @"Microsoft\Edge\User Data\Default\Extensions");
        yield return Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data\Default\Extensions");
        yield return Path.Combine(app, @"Opera Software\Opera Stable\Extensions");
        yield return Path.Combine(app, @"Mozilla\Firefox\Profiles");
    }

    public void Dispose() => Stop();
}
