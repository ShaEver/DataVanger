using System;

namespace DataVanger.Scheduling.Models;

public sealed class RetryPolicy
{
    public int MaxAttempts { get; set; } = 1;
    public TimeSpan BackoffBase { get; set; } = TimeSpan.FromMinutes(5);

    public static RetryPolicy NoRetry => new() { MaxAttempts = 1, BackoffBase = TimeSpan.Zero };

    public TimeSpan ComputeDelay(int attemptIndex)
    {
        if (BackoffBase <= TimeSpan.Zero) return TimeSpan.Zero;

        int factor = Math.Max(0, attemptIndex);
        long multiplier = 1L << Math.Min(factor, 6);

        if (BackoffBase.Ticks > TimeSpan.MaxValue.Ticks / multiplier)
            return TimeSpan.MaxValue;

        return TimeSpan.FromTicks(BackoffBase.Ticks * multiplier);
    }
}
