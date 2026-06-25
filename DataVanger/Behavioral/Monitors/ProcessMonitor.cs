using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Behavioral.Monitors;

/// <summary>
/// Polling-based process monitor.
///
/// This is the safe baseline: no ETW, no driver, no native hooks. It
/// uses <see cref="Process.GetProcesses"/> every <see cref="PollInterval"/>
/// to diff live processes against the last snapshot, publishing
/// <see cref="BehavioralEventKind.ProcessStart"/> and
/// <see cref="BehavioralEventKind.ProcessEnd"/> events. A future PR can
/// replace this with an ETW-backed provider — the rule engine will not
/// notice the change because both providers publish through the same
/// event bus.
///
/// Polling is intentionally conservative (default: 2 s). Each pass
/// avoids per-process exceptions poisoning the run; failures degrade
/// to "no event for that pid".
/// </summary>
public sealed class ProcessMonitor : IDisposable
{
    private readonly IBehavioralEventBus _bus;
    private readonly TimeSpan _pollInterval;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<int, KnownProcess> _known = new();
    private Task? _loop;
    public TimeSpan PollInterval => _pollInterval;
    public int KnownCount => _known.Count;

    public ProcessMonitor(IBehavioralEventBus bus, TimeSpan? pollInterval = null)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(2);
    }

    public void Start()
    {
        if (_loop != null) return;
        _loop = Task.Run(() => Loop(_cts.Token));
    }

    private async Task Loop(CancellationToken token)
    {
        // First pass: seed without emitting events.
        try { Snapshot(emit: false); } catch (Exception) { /* First-pass seed is best-effort - ignore and start polling. */ }
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_pollInterval, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            try { Snapshot(emit: true); }
            catch { /* never fail the loop */ }
        }
    }

    /// <summary>Perform an immediate snapshot. Useful for tests / first-pass seeding.</summary>
    public void SnapshotNow(bool emit) => Snapshot(emit);

    private void Snapshot(bool emit)
    {
        var live = new ConcurrentDictionary<int, byte>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                live[proc.Id] = 1;
                if (_known.ContainsKey(proc.Id)) continue;
                var info = SafeRead(proc);
                _known[proc.Id] = info;
                if (!emit) continue;

                _bus.Publish(new BehavioralEvent(
                    kind: BehavioralEventKind.ProcessStart,
                    pid: info.Pid,
                    parentPid: info.ParentPid,
                    processName: info.Name,
                    imagePath: info.ImagePath,
                    commandLine: "" /* polling cannot reliably get the command line without WMI/ETW */,
                    targetPath: "",
                    extraTag: "polled",
                    severity: BehavioralSeverity.Info,
                    description: $"Processo iniciado: {info.Name}",
                    timestampUtc: DateTime.UtcNow));
            }
            catch (Exception)
            {
                // Protected or exited process during inspection/publish - skip and continue enumeration.
            }
            finally
            {
                try { proc.Dispose(); } catch (Exception) { /* Dispose may throw on an already-disposed process handle - ignore. */ }
            }
        }

        // Emit terminations for pids no longer present.
        foreach (var kvp in _known)
        {
            if (live.ContainsKey(kvp.Key)) continue;
            _known.TryRemove(kvp.Key, out var gone);
            if (!emit || gone is null) continue;
            _bus.Publish(new BehavioralEvent(
                kind: BehavioralEventKind.ProcessEnd,
                pid: gone.Pid,
                parentPid: gone.ParentPid,
                processName: gone.Name,
                imagePath: gone.ImagePath,
                commandLine: "",
                targetPath: "",
                extraTag: "polled",
                severity: BehavioralSeverity.Info,
                description: $"Processo terminou: {gone.Name}",
                timestampUtc: DateTime.UtcNow));
        }
    }

    private static KnownProcess SafeRead(Process p)
    {
        string name = "";
        string path = "";
        try { name = (p.ProcessName ?? "") + ".exe"; } catch (Exception) { /* ProcessName throws for protected/exited processes - leave name empty. */ }
        try { path = p.MainModule?.FileName ?? ""; } catch (Exception) { /* MainModule throws Win32Exception/InvalidOperationException for protected/exited processes - leave path empty. */ }
        if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(path))
        {
            try { name = Path.GetFileName(path); } catch (Exception) { /* Malformed path - leave name empty. */ }
        }
        return new KnownProcess(p.Id, /* parent unknown via System.Diagnostics */ 0, name, path);
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        _cts.Dispose();
    }

    private sealed class KnownProcess
    {
        public KnownProcess(int pid, int parentPid, string name, string imagePath)
        {
            Pid = pid; ParentPid = parentPid; Name = name; ImagePath = imagePath;
        }
        public int Pid { get; }
        public int ParentPid { get; }
        public string Name { get; }
        public string ImagePath { get; }
    }
}
