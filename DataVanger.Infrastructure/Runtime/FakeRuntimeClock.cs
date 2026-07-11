using System;

namespace DataVanger.Infrastructure.Runtime;

/// <summary>
/// Deterministic, manually-advanced clock for tests. Never sleeps.
/// </summary>
public sealed class FakeRuntimeClock : IRuntimeClock
{
    private DateTimeOffset _now;

    public FakeRuntimeClock() : this(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)) { }

    public FakeRuntimeClock(DateTimeOffset start) => _now = start;

    public DateTimeOffset UtcNow => _now;

    public void Advance(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(delta));
        _now = _now.Add(delta);
    }

    public void Set(DateTimeOffset value) => _now = value;
}
