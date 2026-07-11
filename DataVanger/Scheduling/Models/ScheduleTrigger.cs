using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Scheduling.Models;

/// <summary>
/// Pure data describing WHEN a scheduled job is due. All time fields are
/// stored in UTC; <see cref="ComputeNextRunUtc"/> is total and never throws.
/// </summary>
public sealed class ScheduleTrigger
{
    public ScheduleTriggerKind Kind { get; set; } = ScheduleTriggerKind.OneTime;

    /// <summary>Anchor instant for OneTime / first run of recurring triggers.</summary>
    public DateTime StartUtc { get; set; }

    /// <summary>Used by <see cref="ScheduleTriggerKind.Interval"/>.</summary>
    public TimeSpan Interval { get; set; }

    /// <summary>Days selected for <see cref="ScheduleTriggerKind.Weekly"/>.</summary>
    public List<DayOfWeek> DaysOfWeek { get; set; } = new();

    /// <summary>Day-of-month (1..28) for <see cref="ScheduleTriggerKind.Monthly"/>.</summary>
    public int DayOfMonth { get; set; } = 1;

    /// <summary>
    /// Computes the next run after <paramref name="afterUtc"/>. Returns
    /// <c>null</c> when the trigger has no future occurrence (eg. a OneTime
    /// trigger already executed).
    /// </summary>
    public DateTime? ComputeNextRunUtc(DateTime afterUtc, DateTime? lastRunUtc)
    {
        DateTime anchor = DateTime.SpecifyKind(StartUtc, DateTimeKind.Utc);
        afterUtc = DateTime.SpecifyKind(afterUtc, DateTimeKind.Utc);

        switch (Kind)
        {
            case ScheduleTriggerKind.OneTime:
                return lastRunUtc.HasValue ? null : anchor;

            case ScheduleTriggerKind.Startup:
                // Startup triggers fire once per process startup; the
                // scheduler signals startup explicitly so this is just an
                // anchor — treat like OneTime relative to last run.
                return lastRunUtc.HasValue ? null : anchor;

            case ScheduleTriggerKind.Daily:
                return NextDaily(anchor, afterUtc);

            case ScheduleTriggerKind.Weekly:
                return NextWeekly(anchor, afterUtc);

            case ScheduleTriggerKind.Monthly:
                return NextMonthly(anchor, afterUtc);

            case ScheduleTriggerKind.Interval:
                return NextInterval(anchor, afterUtc, lastRunUtc);
        }
        return null;
    }

    private static DateTime NextDaily(DateTime anchor, DateTime afterUtc)
    {
        var time = anchor.TimeOfDay;
        var candidate = afterUtc.Date + time;
        if (candidate < anchor) candidate = anchor;
        while (candidate <= afterUtc) candidate = candidate.AddDays(1);
        return DateTime.SpecifyKind(candidate, DateTimeKind.Utc);
    }

    private DateTime? NextWeekly(DateTime anchor, DateTime afterUtc)
    {
        var days = DaysOfWeek?.Distinct().ToList() ?? new List<DayOfWeek>();
        if (days.Count == 0) days = new List<DayOfWeek> { anchor.DayOfWeek };
        var time = anchor.TimeOfDay;
        for (int i = 0; i < 14; i++)
        {
            var d = afterUtc.Date.AddDays(i);
            if (!days.Contains(d.DayOfWeek)) continue;
            var candidate = DateTime.SpecifyKind(d + time, DateTimeKind.Utc);
            if (candidate < anchor) continue;
            if (candidate > afterUtc) return candidate;
        }
        return null;
    }

    private DateTime NextMonthly(DateTime anchor, DateTime afterUtc)
    {
        int day = Math.Clamp(DayOfMonth, 1, 28);
        var time = anchor.TimeOfDay;
        var probe = new DateTime(afterUtc.Year, afterUtc.Month, day, 0, 0, 0, DateTimeKind.Utc) + time;
        if (probe < anchor) probe = new DateTime(anchor.Year, anchor.Month, day, 0, 0, 0, DateTimeKind.Utc) + time;
        while (probe <= afterUtc) probe = probe.AddMonths(1);
        return DateTime.SpecifyKind(probe, DateTimeKind.Utc);
    }

    private DateTime? NextInterval(DateTime anchor, DateTime afterUtc, DateTime? lastRunUtc)
    {
        if (Interval <= TimeSpan.Zero) return null;
        var basis = lastRunUtc ?? anchor;
        var candidate = basis + Interval;
        if (candidate <= afterUtc)
        {
            // Snap forward to the next slot strictly after afterUtc.
            var deltaTicks = afterUtc.Ticks - basis.Ticks;
            long slots = deltaTicks / Interval.Ticks + 1;
            candidate = basis.AddTicks(slots * Interval.Ticks);
        }
        return DateTime.SpecifyKind(candidate, DateTimeKind.Utc);
    }
}
