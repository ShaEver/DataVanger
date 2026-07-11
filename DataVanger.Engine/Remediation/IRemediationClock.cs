using System;

namespace DataVanger.Engine.Remediation;

/// <summary>Abstracts "now" so journal timestamps are deterministic in tests.
/// Reading the clock is not a destructive operation.</summary>
public interface IRemediationClock
{
    DateTimeOffset UtcNow { get; }
}

/// <summary>Default clock backed by the system UTC time.</summary>
public sealed class SystemRemediationClock : IRemediationClock
{
    public static SystemRemediationClock Instance { get; } = new();
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
