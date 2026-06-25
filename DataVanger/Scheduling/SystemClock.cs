using System;
using DataVanger.Scheduling.Abstractions;

namespace DataVanger.Scheduling;

public sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new();
    public DateTime UtcNow => DateTime.UtcNow;
}
