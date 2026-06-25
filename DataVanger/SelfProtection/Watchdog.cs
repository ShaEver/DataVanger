using System;
using System.Collections.Generic;

namespace DataVanger.SelfProtection;

/// <summary>
/// Tick-driven watchdog.
///
/// The watchdog never runs its own loop, never owns a timer, never
/// spawns a thread. Callers ask it to observe a registered component by
/// calling <see cref="Observe"/> with a current timestamp; the watchdog
/// returns an immutable <see cref="WatchdogObservation"/> describing
/// what happened.
///
/// Safety properties:
///   - <see cref="WatchdogPolicy.MaxWatchdogAttempts"/> bounds the number
///     of recovery attempts per component (no restart storms),
///   - <see cref="WatchdogPolicy.WatchdogCooldown"/> enforces a minimum
///     delay between two attempts on the same component,
///   - in <see cref="SelfProtectionMode.Development"/> the recovery
///     callback is NEVER invoked — the watchdog only records
///     observations so tests/IDEs cannot be impacted.
/// </summary>
public sealed class Watchdog
{
    private readonly SelfProtectionPolicy _policy;
    private readonly ITamperEventSink? _sink;
    private readonly Dictionary<string, ComponentState> _state = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public Watchdog(SelfProtectionPolicy policy, ITamperEventSink? sink = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _sink = sink;
    }

    /// <summary>
    /// Register a component for observation. The <paramref name="healthCheck"/>
    /// returns <c>true</c> when the component is healthy. The optional
    /// <paramref name="recovery"/> callback is invoked in production mode
    /// when the component becomes unhealthy and the cooldown/retry budget
    /// permits. Re-registering replaces the previous callbacks.
    /// </summary>
    public void Register(
        string component,
        Func<bool> healthCheck,
        Action? recovery = null)
    {
        if (string.IsNullOrWhiteSpace(component)) throw new ArgumentException("component", nameof(component));
        if (healthCheck is null) throw new ArgumentNullException(nameof(healthCheck));
        lock (_gate)
        {
            _state[component] = new ComponentState(healthCheck, recovery);
        }
    }

    /// <summary>Currently registered component names (snapshot).</summary>
    public IReadOnlyCollection<string> Components
    {
        get { lock (_gate) return new List<string>(_state.Keys); }
    }

    /// <summary>
    /// Observe a single registered component. Returns
    /// <see cref="WatchdogOutcome.Healthy"/> if no action was needed.
    /// </summary>
    public WatchdogObservation Observe(string component, DateTime? nowUtc = null)
    {
        var now = nowUtc?.ToUniversalTime() ?? DateTime.UtcNow;
        ComponentState? state;
        lock (_gate)
        {
            if (!_state.TryGetValue(component, out state) || state is null)
            {
                return new WatchdogObservation(component, WatchdogOutcome.Healthy, 0, now, "not registered");
            }
        }

        bool healthy;
        try { healthy = state.HealthCheck(); }
        catch (Exception ex)
        {
            try { _policy.Diagnostics?.Invoke($"watchdog health check threw for {component}: {ex.GetType().Name}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
            healthy = false;
        }

        if (healthy)
        {
            state.ConsecutiveFailures = 0;
            return new WatchdogObservation(component, WatchdogOutcome.Healthy, state.AttemptCount, now, "healthy");
        }

        // Cooldown.
        if (state.LastAttemptUtc != default && (now - state.LastAttemptUtc) < _policy.WatchdogCooldown)
        {
            return new WatchdogObservation(component, WatchdogOutcome.OnCooldown, state.AttemptCount, now,
                $"cooldown active ({_policy.WatchdogCooldown.TotalSeconds:0}s)");
        }

        // Retry budget.
        if (state.AttemptCount >= _policy.MaxWatchdogAttempts)
        {
            // Emit a single tamper signal that the watchdog gave up, then
            // stop trying. This prevents restart storms by construction.
            EmitGaveUp(component, now, state.AttemptCount);
            return new WatchdogObservation(component, WatchdogOutcome.GaveUp, state.AttemptCount, now,
                $"exceeded retry budget ({_policy.MaxWatchdogAttempts})");
        }

        state.AttemptCount++;
        state.ConsecutiveFailures++;
        state.LastAttemptUtc = now;

        // In development mode the watchdog records the observation but
        // does NOT invoke the recovery callback — tests and IDEs must
        // never be affected by self-protection behavior.
        if (_policy.Mode == SelfProtectionMode.Development || state.Recovery is null)
        {
            return new WatchdogObservation(component, WatchdogOutcome.RecoveryAttempted, state.AttemptCount, now,
                $"unhealthy (dev-mode/no-op recovery, attempt {state.AttemptCount})");
        }

        try
        {
            state.Recovery();
            return new WatchdogObservation(component, WatchdogOutcome.RecoveryAttempted, state.AttemptCount, now,
                $"recovery invoked (attempt {state.AttemptCount})");
        }
        catch (Exception ex)
        {
            try { _policy.Diagnostics?.Invoke($"watchdog recovery threw for {component}: {ex.GetType().Name}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
            return new WatchdogObservation(component, WatchdogOutcome.RecoveryFailed, state.AttemptCount, now,
                $"recovery threw {ex.GetType().Name}");
        }
    }

    /// <summary>Reset attempt counters for a component (e.g. after a clean shutdown).</summary>
    public void Reset(string component)
    {
        if (string.IsNullOrWhiteSpace(component)) return;
        lock (_gate)
        {
            if (_state.TryGetValue(component, out var s) && s is not null)
            {
                s.AttemptCount = 0;
                s.ConsecutiveFailures = 0;
                s.LastAttemptUtc = default;
            }
        }
    }

    private void EmitGaveUp(string component, DateTime now, int attempts)
    {
        try
        {
            _sink?.Publish(new TamperEvent(
                kind: TamperKind.WatchdogGaveUp,
                severity: TamperSeverity.Medium,
                component: component,
                targetPath: "",
                description: $"Watchdog desistiu após {attempts} tentativas.",
                timestampUtc: now));
        }
        catch (Exception ex)
        {
            try { _policy.Diagnostics?.Invoke($"watchdog give-up emit failed: {ex.GetType().Name}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
        }
    }

    private sealed class ComponentState
    {
        public ComponentState(Func<bool> healthCheck, Action? recovery)
        {
            HealthCheck = healthCheck;
            Recovery = recovery;
        }
        public Func<bool> HealthCheck { get; }
        public Action? Recovery { get; }
        public int AttemptCount;
        public int ConsecutiveFailures;
        public DateTime LastAttemptUtc;
    }
}
