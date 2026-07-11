using System;
using DataVanger.Scheduling.Abstractions;

namespace DataVanger.Scheduling;

/// <summary>
/// Test-friendly clock. Lives in the production assembly so the scheduler
/// surface stays trim and tests do not need to redefine the abstraction.
/// </summary>
public sealed class FakeClock : IClock
{
    private DateTime _now;

    public FakeClock() : this(new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)) { }
    public FakeClock(DateTime startUtc)
    {
        _now = DateTime.SpecifyKind(startUtc, DateTimeKind.Utc);
    }

    public DateTime UtcNow => _now;

    public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    public void SetUtc(DateTime utc) => _now = DateTime.SpecifyKind(utc, DateTimeKind.Utc);
}
