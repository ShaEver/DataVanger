using System;
using DataVanger.Behavioral;
using DataVanger.Runtime.Amsi;
using DataVanger.Runtime.Etw;

namespace DataVanger.Runtime;

/// <summary>
/// High-level facade for the runtime telemetry subsystem.
///
/// Composes:
///   - one ETW provider (no-op in this build, real one in a future PR),
///   - one AMSI provider (in-memory content analyzer + bypass detector),
///   - a bridge that forwards normalized events onto a
///     <see cref="BehavioralEngine"/>'s bus.
///
/// The service is opt-in: the rest of DataVanger does not depend on it
/// being constructed. When it IS constructed, every component fails
/// closed if its backend is missing — there is no scenario where this
/// class throws because the host is not Windows / not elevated / not
/// AMSI-aware.
/// </summary>
public sealed class RuntimeTelemetryService : IDisposable
{
    private readonly RuntimeTelemetryBridge _bridge;
    private readonly IEtwTelemetryProvider _etw;
    private readonly IAmsiTelemetryProvider _amsi;
    private readonly Action<string>? _diagnostics;
    private int _started;
    private int _disposed;

    public IEtwTelemetryProvider Etw => _etw;
    public IAmsiTelemetryProvider Amsi => _amsi;
    public RuntimeTelemetryBridge Bridge => _bridge;
    public bool IsStarted => System.Threading.Volatile.Read(ref _started) == 1;

    public RuntimeTelemetryService(
        BehavioralEngine engine,
        EtwProviderMode etwMode = EtwProviderMode.Auto,
        AmsiProviderMode amsiMode = AmsiProviderMode.Auto,
        RuntimeTelemetryThrottle? throttle = null,
        Action<string>? diagnostics = null)
        : this(engine?.Bus ?? throw new ArgumentNullException(nameof(engine)),
            etwMode, amsiMode, throttle, diagnostics)
    {
    }

    public RuntimeTelemetryService(
        IBehavioralEventBus bus,
        EtwProviderMode etwMode = EtwProviderMode.Auto,
        AmsiProviderMode amsiMode = AmsiProviderMode.Auto,
        RuntimeTelemetryThrottle? throttle = null,
        Action<string>? diagnostics = null)
    {
        if (bus is null) throw new ArgumentNullException(nameof(bus));
        _diagnostics = diagnostics;
        _bridge = new RuntimeTelemetryBridge(bus, throttle, diagnostics);
        _etw = EtwProviderFactory.Create(etwMode);
        _amsi = AmsiProviderFactory.Create(amsiMode);
        _bridge.AttachEtw(_etw);
        _bridge.AttachAmsi(_amsi);
    }

    /// <summary>Start both providers. Safe to call multiple times.</summary>
    public RuntimeTelemetryServiceStatus Start()
    {
        if (System.Threading.Interlocked.Exchange(ref _started, 1) == 1)
            return Status();
        RuntimeProviderState etwState;
        RuntimeProviderState amsiState;
        try { etwState = _etw.Start(); }
        catch (Exception ex)
        {
            etwState = RuntimeProviderState.Failed;
            Diag($"etw start failed: {ex.GetType().Name}: {ex.Message}");
        }
        try { amsiState = _amsi.Start(); }
        catch (Exception ex)
        {
            amsiState = RuntimeProviderState.Failed;
            Diag($"amsi start failed: {ex.GetType().Name}: {ex.Message}");
        }
        return new RuntimeTelemetryServiceStatus(etwState, amsiState,
            _etw.IsHostSupported, _amsi.IsHostSupported);
    }

    public RuntimeTelemetryServiceStatus Status()
        => new RuntimeTelemetryServiceStatus(_etw.State, _amsi.State,
            _etw.IsHostSupported, _amsi.IsHostSupported);

    /// <summary>Submit a script content sample through the AMSI pipeline.</summary>
    public int SubmitAmsiContent(string source, string scriptContent, int pid)
    {
        if (System.Threading.Volatile.Read(ref _disposed) == 1) return 0;
        try { return _amsi.SubmitContent(source, scriptContent, pid); }
        catch (Exception ex)
        {
            Diag($"amsi submit failed: {ex.GetType().Name}: {ex.Message}");
            return 0;
        }
    }

    private void Diag(string message)
    {
        try { _diagnostics?.Invoke(message); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
    }

    public void Dispose()
    {
        if (System.Threading.Interlocked.Exchange(ref _disposed, 1) == 1) return;
        try { _bridge.Dispose(); } catch (Exception) { /* Dispose may throw on already-disposed or never-started instances - ignore. */ }
        try { _etw.Dispose(); } catch (Exception) { /* Dispose may throw on already-disposed or never-started instances - ignore. */ }
        try { _amsi.Dispose(); } catch (Exception) { /* Dispose may throw on already-disposed or never-started instances - ignore. */ }
    }
}

/// <summary>Snapshot of provider lifecycle state.</summary>
public sealed class RuntimeTelemetryServiceStatus
{
    public RuntimeTelemetryServiceStatus(
        RuntimeProviderState etw, RuntimeProviderState amsi,
        bool etwHostSupported, bool amsiHostSupported)
    {
        EtwState = etw;
        AmsiState = amsi;
        EtwHostSupported = etwHostSupported;
        AmsiHostSupported = amsiHostSupported;
    }

    public RuntimeProviderState EtwState { get; }
    public RuntimeProviderState AmsiState { get; }
    public bool EtwHostSupported { get; }
    public bool AmsiHostSupported { get; }

    /// <summary>True when ETW is actually emitting events (real or mock).</summary>
    public bool EtwActive => EtwState == RuntimeProviderState.Running || EtwState == RuntimeProviderState.RunningMock;

    /// <summary>True when AMSI is actually emitting events (real or mock).</summary>
    public bool AmsiActive => AmsiState == RuntimeProviderState.Running || AmsiState == RuntimeProviderState.RunningMock;

    public override string ToString() => $"etw={EtwState}/host={EtwHostSupported} amsi={AmsiState}/host={AmsiHostSupported}";
}
