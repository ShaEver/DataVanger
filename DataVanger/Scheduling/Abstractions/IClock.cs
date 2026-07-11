using System;

namespace DataVanger.Scheduling.Abstractions;

/// <summary>
/// Deterministic time source for the scheduler. Production code uses
/// <see cref="SystemClock"/>; tests inject <see cref="FakeClock"/> so
/// scheduling logic can be exercised without wall-clock delays.
/// </summary>
public interface IClock
{
    DateTime UtcNow { get; }
}
