using System;
using System.Collections.Generic;

namespace DataVanger.SelfProtection;

/// <summary>
/// Fan-out tamper sink: forwards every event to all configured child
/// sinks. A child sink that throws is isolated — other sinks still see
/// the event.
/// </summary>
public sealed class CompositeTamperSink : ITamperEventSink
{
    private readonly IReadOnlyList<ITamperEventSink> _sinks;
    private readonly Action<string>? _diagnostics;

    public CompositeTamperSink(IEnumerable<ITamperEventSink> sinks, Action<string>? diagnostics = null)
    {
        if (sinks is null) throw new ArgumentNullException(nameof(sinks));
        var list = new List<ITamperEventSink>();
        foreach (var sink in sinks)
            if (sink is not null) list.Add(sink);
        _sinks = list;
        _diagnostics = diagnostics;
    }

    public int SinkCount => _sinks.Count;

    public bool Publish(TamperEvent ev)
    {
        if (ev is null) return false;
        bool anyAccepted = false;
        for (int i = 0; i < _sinks.Count; i++)
        {
            try
            {
                if (_sinks[i].Publish(ev)) anyAccepted = true;
            }
            catch (Exception ex)
            {
                try { _diagnostics?.Invoke($"composite tamper sink child threw: {ex.GetType().Name}: {ex.Message}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
            }
        }
        return anyAccepted;
    }
}
