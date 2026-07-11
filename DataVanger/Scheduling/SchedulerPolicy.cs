using System;
using DataVanger.Scheduling.Models;

namespace DataVanger.Scheduling;

/// <summary>
/// Centralizes policy knobs the orchestrator consults for overlap,
/// retry/backoff and missed-run handling. Kept as plain values so tests
/// can construct it without DI ceremony.
/// </summary>
public sealed class SchedulerPolicy
{
    private static readonly TimeSpan DefaultMaxBackoff = TimeSpan.FromHours(1);

    /// <summary>Maximum concurrent running jobs. The scheduler enforces
    /// non-overlap by default (value = 1) to honour the safety contract.</summary>
    public int MaxConcurrentJobs { get; init; } = 1;

    /// <summary>Upper bound applied on top of any per-job retry policy so
    /// a misconfigured definition cannot create an unbounded retry loop.</summary>
    public int MaxRetryAttemptsCeiling { get; init; } = 6;

    /// <summary>Default missed-run policy used when a definition does
    /// not override it.</summary>
    public MissedRunPolicy DefaultMissedRunPolicy { get; init; } = MissedRunPolicy.Skip;

    public TimeSpan MaxBackoff { get; init; } = TimeSpan.FromHours(1);

    public int EffectiveMaxConcurrentJobs()
        => MaxConcurrentJobs <= 0 ? 1 : MaxConcurrentJobs;

    public int EffectiveMaxAttempts(RetryPolicy retry)
    {
        int requested = retry?.MaxAttempts ?? 1;
        int ceiling = MaxRetryAttemptsCeiling <= 0 ? 1 : MaxRetryAttemptsCeiling;
        return Math.Clamp(requested, 1, ceiling);
    }

    public TimeSpan EffectiveBackoff(RetryPolicy retry, int attemptIndex)
    {
        if (retry == null) return TimeSpan.Zero;

        var cap = MaxBackoff < TimeSpan.Zero ? DefaultMaxBackoff : MaxBackoff;
        var delay = retry.ComputeDelay(attemptIndex);
        if (delay < TimeSpan.Zero) return TimeSpan.Zero;
        return delay > cap ? cap : delay;
    }
}
