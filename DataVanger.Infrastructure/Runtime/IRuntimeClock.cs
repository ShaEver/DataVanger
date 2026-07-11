using System;

namespace DataVanger.Infrastructure.Runtime;

/// <summary>
/// Thin clock abstraction so debounce, stability probing, and scan
/// caching can be driven by a fake clock in deterministic tests
/// instead of wall-clock sleeps.
/// </summary>
public interface IRuntimeClock
{
    DateTimeOffset UtcNow { get; }
}
