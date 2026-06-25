using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Scheduling.Abstractions;
using DataVanger.Scheduling.Models;

namespace DataVanger.Scheduling;

/// <summary>
/// Advanced scheduler orchestrator.
///
/// Design notes:
///   * Deterministic by construction — every time decision goes through
///     <see cref="IClock"/>. Tests advance a <see cref="FakeClock"/>; no
///     wall-clock waits or background timers live in this class.
///   * "Tick" model — host code calls <see cref="ProcessDueAsync"/>
///     (from a timer, UI dispatcher or test). The scheduler never spins
///     up its own thread, satisfying "Do NOT add aggressive background
///     services that interfere with tests".
///   * The scheduler ORCHESTRATES; it never classifies findings. All
///     classification decisions remain in <c>ThreatClassificationPolicy</c>.
/// </summary>
public sealed class ScanScheduler
{
    private readonly IClock _clock;
    private readonly ISchedulerStore _store;
    private readonly IScheduledScanRunner _runner;
    private readonly SchedulerPolicy _policy;
    private readonly Action<string>? _log;

    private readonly object _gate = new();
    private readonly Dictionary<string, ScheduledJobDefinition> _jobs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ScheduledJobStatus> _status = new(StringComparer.Ordinal);
    private readonly HashSet<string> _runningJobIds = new(StringComparer.Ordinal);
    private bool _paused;

    public ScanScheduler(
        IClock clock,
        ISchedulerStore store,
        IScheduledScanRunner runner,
        SchedulerPolicy? policy = null,
        Action<string>? log = null)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _policy = policy ?? new SchedulerPolicy();
        _log = log;
        ReloadFromStore();
    }

    // -- Lifecycle ----------------------------------------------------------

    public void Pause()  { lock (_gate) _paused = true; }
    public void Resume() { lock (_gate) _paused = false; }
    public bool IsPaused { get { lock (_gate) return _paused; } }

    // -- CRUD ---------------------------------------------------------------

    public void AddOrUpdate(ScheduledJobDefinition job)
    {
        if (job == null) throw new ArgumentNullException(nameof(job));
        if (string.IsNullOrWhiteSpace(job.Id)) job.Id = Guid.NewGuid().ToString("N");
        lock (_gate)
        {
            _jobs[job.Id] = job;
            if (!_status.TryGetValue(job.Id, out var st))
            {
                st = new ScheduledJobStatus { JobId = job.Id };
                _status[job.Id] = st;
            }
            st.NextRunUtc = ComputeNext(job, st);
            PersistLocked();
        }
    }

    public bool Remove(string jobId)
    {
        lock (_gate)
        {
            bool removed = _jobs.Remove(jobId);
            _status.Remove(jobId);
            if (removed) PersistLocked();
            return removed;
        }
    }

    public bool SetEnabled(string jobId, bool enabled)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId, out var job)) return false;
            job.Enabled = enabled;
            if (_status.TryGetValue(jobId, out var st))
                st.NextRunUtc = enabled ? ComputeNext(job, st) : null;
            PersistLocked();
            return true;
        }
    }

    public IReadOnlyList<ScheduledJobDefinition> Jobs
    {
        get { lock (_gate) return _jobs.Values.ToList(); }
    }

    public ScheduledJobStatus? GetStatus(string jobId)
    {
        lock (_gate) return _status.TryGetValue(jobId, out var st) ? Clone(st) : null;
    }

    public SchedulerStatus Snapshot()
    {
        lock (_gate)
        {
            var status = new SchedulerStatus
            {
                Paused = _paused,
                SnapshotUtc = _clock.UtcNow,
            };
            foreach (var job in _jobs.Values)
            {
                _status.TryGetValue(job.Id, out var st);
                status.Jobs.Add(new SchedulerJobStatusSnapshot
                {
                    JobId = job.Id,
                    Name = job.Name,
                    Enabled = job.Enabled,
                    IsRunning = st?.IsRunning ?? false,
                    NextRunUtc = st?.NextRunUtc,
                    LastRunUtc = st?.LastRunUtc,
                    LastOutcome = st?.LastOutcome ?? JobRunOutcome.NotRun,
                    ConsecutiveFailures = st?.ConsecutiveFailures ?? 0,
                });
            }
            return status;
        }
    }

    public IReadOnlyList<ScheduledJobExecution> History() => _store.LoadHistory();

    // -- Tick ---------------------------------------------------------------

    /// <summary>
    /// Picks up every job whose next-run time has passed and executes
    /// them sequentially (limited by <see cref="SchedulerPolicy.MaxConcurrentJobs"/>).
    /// Returns the executions that completed during this tick.
    /// </summary>
    public async Task<IReadOnlyList<ScheduledJobExecution>> ProcessDueAsync(CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested) return Array.Empty<ScheduledJobExecution>();

        List<ScheduledJobDefinition> due;
        lock (_gate)
        {
            if (_paused) return Array.Empty<ScheduledJobExecution>();
            due = SelectDueLocked(_clock.UtcNow);
        }

        var results = new List<ScheduledJobExecution>(due.Count);
        foreach (var job in due)
        {
            if (cancellationToken.IsCancellationRequested) break;
            if (!TryBeginRun(job.Id)) continue;
            ScheduledJobExecution exec;
            try
            {
                exec = await ExecuteAsync(job, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                EndRun(job.Id);
            }
            results.Add(exec);
        }
        return results;
    }

    private List<ScheduledJobDefinition> SelectDueLocked(DateTime nowUtc)
    {
        var due = new List<ScheduledJobDefinition>();
        foreach (var job in _jobs.Values)
        {
            if (!job.Enabled) continue;
            if (!_status.TryGetValue(job.Id, out var st)) continue;
            if (st.IsRunning) continue;

            // Pending retry takes precedence over — and gates — normal next-run:
            // while a retry is pending, NextRunUtc must NOT trigger a parallel
            // run, otherwise an always-failing job would execute on every tick.
            if (st.PendingRetryUtc.HasValue)
            {
                if (st.PendingRetryUtc.Value <= nowUtc) due.Add(job);
                continue;
            }

            if (!st.NextRunUtc.HasValue) continue;
            if (st.NextRunUtc.Value <= nowUtc) due.Add(job);
        }
        // Order: lower NextRunUtc first so the oldest miss runs first.
        due.Sort((a, b) =>
        {
            var ax = _status[a.Id].PendingRetryUtc ?? _status[a.Id].NextRunUtc ?? DateTime.MaxValue;
            var bx = _status[b.Id].PendingRetryUtc ?? _status[b.Id].NextRunUtc ?? DateTime.MaxValue;
            return ax.CompareTo(bx);
        });

        int cap = _policy.EffectiveMaxConcurrentJobs();
        if (due.Count > cap) due = due.GetRange(0, cap);
        return due;
    }

    private bool TryBeginRun(string jobId)
    {
        lock (_gate)
        {
            if (_runningJobIds.Count >= _policy.EffectiveMaxConcurrentJobs()) return false;
            if (!_runningJobIds.Add(jobId)) return false;
            if (_status.TryGetValue(jobId, out var st)) st.IsRunning = true;
            return true;
        }
    }

    private void EndRun(string jobId)
    {
        lock (_gate)
        {
            _runningJobIds.Remove(jobId);
            if (_status.TryGetValue(jobId, out var st)) st.IsRunning = false;
        }
    }

    private async Task<ScheduledJobExecution> ExecuteAsync(
        ScheduledJobDefinition job,
        CancellationToken cancellationToken)
    {
        int attempt;
        lock (_gate)
        {
            attempt = _status[job.Id].PendingRetryAttempt + 1;
        }

        var startedUtc = _clock.UtcNow;
        ScheduledRunResult result;
        try
        {
            result = await _runner.RunAsync(job, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            result = ScheduledRunResult.Cancelled();
        }
        catch (Exception ex)
        {
            result = new ScheduledRunResult
            {
                Outcome = JobRunOutcome.Failed,
                Message = ex.Message,
            };
            SafeLog($"[scheduler] job '{job.Name}' threw: {ex.GetType().Name}");
        }
        var completedUtc = _clock.UtcNow;

        var execution = new ScheduledJobExecution
        {
            JobId = job.Id,
            JobName = job.Name,
            StartedUtc = startedUtc,
            CompletedUtc = completedUtc,
            Outcome = result.Outcome,
            FindingsCount = result.FindingsCount,
            AttemptNumber = attempt,
            Message = result.Message,
            ReportPath = result.ReportPath,
        };

        ApplyOutcome(job, execution, result);
        SafeAppendHistory(execution);
        return execution;
    }

    private void ApplyOutcome(
        ScheduledJobDefinition job,
        ScheduledJobExecution execution,
        ScheduledRunResult result)
    {
        lock (_gate)
        {
            if (!_status.TryGetValue(job.Id, out var st)) return;
            st.LastRunUtc = execution.StartedUtc;
            st.LastOutcome = result.Outcome;
            st.LastMessage = result.Message;

            int maxAttempts = _policy.EffectiveMaxAttempts(job.Retry);
            bool isFailure = result.Outcome == JobRunOutcome.Failed;
            bool isSuccessOrTerminal =
                result.Outcome is JobRunOutcome.Success
                    or JobRunOutcome.Skipped
                    or JobRunOutcome.Cancelled;

            if (isFailure && execution.AttemptNumber < maxAttempts)
            {
                st.PendingRetryAttempt = execution.AttemptNumber;
                st.PendingRetryUtc = _clock.UtcNow + _policy.EffectiveBackoff(job.Retry, execution.AttemptNumber);
                st.ConsecutiveFailures++;
            }
            else
            {
                st.PendingRetryAttempt = 0;
                st.PendingRetryUtc = null;
                if (isFailure) st.ConsecutiveFailures++;
                else if (isSuccessOrTerminal) st.ConsecutiveFailures = 0;

                st.NextRunUtc = ComputeNext(job, st);
            }
            PersistLocked();
        }
    }

    private DateTime? ComputeNext(ScheduledJobDefinition job, ScheduledJobStatus st)
    {
        if (job?.Trigger == null) return null;
        try
        {
            return job.Trigger.ComputeNextRunUtc(_clock.UtcNow, st.LastRunUtc);
        }
        catch
        {
            return null;
        }
    }

    // -- Persistence helpers ------------------------------------------------

    private void ReloadFromStore()
    {
        try
        {
            var jobs = _store.LoadJobs();
            var statuses = _store.LoadStatus();
            lock (_gate)
            {
                _jobs.Clear();
                _status.Clear();
                foreach (var j in jobs)
                {
                    if (j == null || string.IsNullOrWhiteSpace(j.Id)) continue;
                    _jobs[j.Id] = SanitizeOnLoad(j);
                }
                foreach (var s in statuses)
                {
                    if (s == null || string.IsNullOrWhiteSpace(s.JobId)) continue;
                    if (!_jobs.ContainsKey(s.JobId)) continue;
                    s.IsRunning = false; // never trust persisted running flag
                    _status[s.JobId] = s;
                }
                foreach (var j in _jobs.Values)
                {
                    if (!_status.ContainsKey(j.Id))
                        _status[j.Id] = new ScheduledJobStatus { JobId = j.Id };
                    var st = _status[j.Id];
                    if (st.NextRunUtc == null) st.NextRunUtc = ComputeNext(j, st);
                }
            }
        }
        catch
        {
            // Corrupt store: start fresh in memory; persistence layer will
            // overwrite with a clean payload on the next change.
        }
    }

    private static ScheduledJobDefinition SanitizeOnLoad(ScheduledJobDefinition job)
    {
        job.Trigger ??= new ScheduleTrigger();
        job.Retry ??= RetryPolicy.NoRetry;
        if (job.Retry.MaxAttempts < 1) job.Retry.MaxAttempts = 1;
        if (job.Trigger.Interval < TimeSpan.Zero) job.Trigger.Interval = TimeSpan.Zero;
        return job;
    }

    private void PersistLocked()
    {
        try
        {
            _store.SaveJobs(_jobs.Values.ToList());
            _store.SaveStatus(_status.Values.ToList());
        }
        catch
        {
            // Already swallowed inside the store; defensive belt-and-braces.
        }
    }

    private void SafeAppendHistory(ScheduledJobExecution exec)
    {
        try { _store.AppendHistory(exec); } catch { /* never fatal */ }
    }

    private static ScheduledJobStatus Clone(ScheduledJobStatus st) => new()
    {
        JobId = st.JobId,
        LastRunUtc = st.LastRunUtc,
        NextRunUtc = st.NextRunUtc,
        LastOutcome = st.LastOutcome,
        LastMessage = st.LastMessage,
        ConsecutiveFailures = st.ConsecutiveFailures,
        PendingRetryAttempt = st.PendingRetryAttempt,
        PendingRetryUtc = st.PendingRetryUtc,
        IsRunning = st.IsRunning,
    };

    private void SafeLog(string msg)
    {
        try { _log?.Invoke(msg); } catch { /* logging must not crash scheduler */ }
    }
}
