using System;

namespace DataVanger.Infrastructure.Runtime;

public sealed class SystemRuntimeClock : IRuntimeClock
{
    public static readonly SystemRuntimeClock Instance = new();
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
