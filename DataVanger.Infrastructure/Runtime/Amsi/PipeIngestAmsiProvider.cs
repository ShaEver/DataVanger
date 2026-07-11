using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Real AMSI provider ingest endpoint, hosted ONLY by the Windows service.
///
/// The matching native shim <c>DataVanger.AmsiProvider.dll</c> is loaded by
/// <c>amsi.dll</c> into every third-party process that calls AMSI. That shim
/// always returns <c>AMSI_RESULT_CLEAN</c> and fire-and-forgets a bounded
/// content prefix over the write-only ingest named pipe this class serves. This
/// class therefore never runs inside a third-party process and never blocks
/// anything — it only OBSERVES, running the exact same analyzers as
/// <see cref="InMemoryAmsiProvider"/> and publishing evidence-only
/// <see cref="RuntimeTelemetryEvent"/>s onto the resident pipeline via
/// <see cref="AmsiRuntimeBridge"/>.
///
/// Hardening (the listener trusts nothing on the wire):
///   - every frame is length-validated and size-capped by
///     <see cref="AmsiIngestProtocol"/>; malformed/oversized/partial frames are
///     dropped with no event and no throw (fail-open on the service side too);
///   - each connection has a hard read deadline so a stalled client cannot pin
///     a server instance;
///   - a bounded rate limiter caps accepted messages per window;
///   - the ACL grants Authenticated Users connect+write ONLY (never read /
///     control), so a low-privilege caller cannot read others' telemetry, and
///     never <c>CreateNewInstance</c>, so it cannot squat a rogue server.
///
/// It NEVER blocks scripts, quarantines, or returns a malware verdict.
/// </summary>
public sealed class PipeIngestAmsiProvider : IAmsiTelemetryProvider
{
    private readonly PipeIngestOptions _options;
    private readonly RateLimiter _rateLimiter;
    private readonly object _gate = new();

    private int _started;
    private int _disposed;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    private long _ingestedFrames;
    private long _rejectedFrames;
    private long _throttledFrames;
    private long _publishedEvents;

    public PipeIngestAmsiProvider(PipeIngestOptions? options = null)
    {
        _options = options ?? PipeIngestOptions.Default;
        _rateLimiter = new RateLimiter(
            Math.Max(1, _options.MaxMessagesPerWindow),
            _options.RateWindow <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : _options.RateWindow);
    }

    public string Name => "pipe-ingest-amsi";
    public RuntimeProviderState State { get; private set; } = RuntimeProviderState.NotStarted;
    public bool IsRunning => Volatile.Read(ref _started) == 1 && Volatile.Read(ref _disposed) == 0;

    /// <summary>The ingest listener is only hostable where named-pipe security
    /// descriptors exist (Windows).</summary>
    public bool IsHostSupported => OperatingSystem.IsWindows();

    public event Action<RuntimeTelemetryEvent>? EventReceived;

    // Diagnostics (bounded counters) — no PII, safe to surface in status.
    public long IngestedFrames => Interlocked.Read(ref _ingestedFrames);
    public long RejectedFrames => Interlocked.Read(ref _rejectedFrames);
    public long ThrottledFrames => Interlocked.Read(ref _throttledFrames);
    public long PublishedEvents => Interlocked.Read(ref _publishedEvents);

    public RuntimeProviderState Start()
    {
        if (Interlocked.Exchange(ref _started, 1) == 1)
            return State;

        // Non-Windows: no OS listener, but out-of-band SubmitContent still works.
        if (!OperatingSystem.IsWindows())
        {
            State = RuntimeProviderState.Unavailable;
            return State;
        }

        try
        {
            var cts = new CancellationTokenSource();
            lock (_gate) { _cts = cts; }
            // Probe once so a squatted/undeletable name surfaces as Failed instead
            // of only failing lazily inside the loop.
            using (var probe = IpcPipeSecurity.CreateIngestServerStream(_options.PipeName, _options.MaxServerInstances))
            {
                // Successful creation proves we own the name; dispose and let the
                // accept loop create the serving instance.
            }

            _acceptLoop = Task.Run(() => AcceptLoopAsync(cts.Token));
            State = RuntimeProviderState.Running;
        }
        catch (Exception)
        {
            // Could not host the listener (name in use, ACL rejected, unsupported).
            // Fail closed on the listener but keep SubmitContent usable; the runtime
            // logs a degraded warning off the returned state.
            State = RuntimeProviderState.Failed;
        }

        return State;
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref _started, 0) == 0)
            return;

        CancellationTokenSource? cts;
        Task? loop;
        lock (_gate)
        {
            cts = _cts;
            loop = _acceptLoop;
            _cts = null;
            _acceptLoop = null;
        }

        try { cts?.Cancel(); } catch (Exception) { /* teardown is best-effort */ }
        try { loop?.Wait(TimeSpan.FromSeconds(2)); } catch (Exception) { /* best-effort */ }
        try { cts?.Dispose(); } catch (Exception) { /* best-effort */ }

        if (State == RuntimeProviderState.Running || State == RuntimeProviderState.Failed)
            State = RuntimeProviderState.Stopped;
    }

    /// <summary>
    /// Out-of-band submission (operator/test driven). Runs the same analyzers as
    /// the pipe path; NOT rate-limited because it is not an untrusted network
    /// source. Never blocks, never returns a verdict.
    /// </summary>
    public int SubmitContent(string source, string scriptContent, int pid)
    {
        if (!IsRunning) return 0;
        return Publish(AmsiContentEvents.Build(Name, source, scriptContent, pid));
    }

    /// <summary>
    /// Decodes and processes exactly one raw ingest frame. Exposed for tests so
    /// the fail-open/rate-limit contract can be verified without opening an OS
    /// pipe. Returns the number of telemetry events published (0 when the frame
    /// is rejected, throttled, or benign). NEVER throws.
    /// </summary>
    public int IngestFrame(ReadOnlySpan<byte> frame)
    {
        if (Volatile.Read(ref _disposed) != 0) return 0;

        if (!AmsiIngestProtocol.TryDecode(frame, out var message))
        {
            Interlocked.Increment(ref _rejectedFrames);
            return 0;
        }

        Interlocked.Increment(ref _ingestedFrames);

        if (!_rateLimiter.TryAcquire())
        {
            Interlocked.Increment(ref _throttledFrames);
            return 0;
        }

        var source = string.IsNullOrEmpty(message.AppName) ? "amsi" : message.AppName;
        return Publish(AmsiContentEvents.Build(Name, source, message.Content, message.Pid));
    }

    private int Publish(System.Collections.Generic.IReadOnlyList<RuntimeTelemetryEvent> events)
    {
        var handler = EventReceived;
        if (handler is null || events.Count == 0) return 0;

        int published = 0;
        for (int i = 0; i < events.Count; i++)
        {
            try
            {
                handler(events[i]);
                published++;
            }
            catch (Exception) { /* sink callback must never throw back into the provider */ }
        }

        if (published > 0) Interlocked.Add(ref _publishedEvents, published);
        return published;
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) return;

        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = IpcPipeSecurity.CreateIngestServerStream(_options.PipeName, _options.MaxServerInstances);
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                await HandleConnectionAsync(server, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                // Fail-open on the service side: a bad connection or a transient
                // pipe error must never kill the listener. Brief backoff so a
                // hard-failing name (e.g. suddenly squatted) does not spin.
                try { await Task.Delay(200, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            finally
            {
                try { server?.Dispose(); } catch (Exception) { /* best-effort */ }
            }
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream server, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ClampReadTimeout(_options.ReadTimeout));

        // One message per connection: read until EOF or the hard cap. The +1 lets
        // us detect an over-cap frame without allocating past the bound.
        var buffer = new byte[AmsiIngestProtocol.MaxFrameBytes + 1];
        int total = 0;

        try
        {
            while (total < buffer.Length)
            {
                int read = await server
                    .ReadAsync(buffer.AsMemory(total, buffer.Length - total), timeout.Token)
                    .ConfigureAwait(false);
                if (read == 0) break; // client finished writing and disconnected
                total += read;
            }
        }
        catch (OperationCanceledException)
        {
            // Read deadline hit or shutdown — drop this connection, keep serving.
            return;
        }
        catch (IOException)
        {
            return; // broken pipe — drop and continue
        }

        if (total > AmsiIngestProtocol.MaxFrameBytes)
        {
            Interlocked.Increment(ref _rejectedFrames);
            return;
        }

        IngestFrame(buffer.AsSpan(0, total));
    }

    private static TimeSpan ClampReadTimeout(TimeSpan value)
    {
        if (value <= TimeSpan.Zero) return TimeSpan.FromSeconds(2);
        return value > TimeSpan.FromSeconds(10) ? TimeSpan.FromSeconds(10) : value;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        Stop();
        EventReceived = null;
    }

    /// <summary>
    /// Minimal monotonic sliding-window limiter. Self-contained on purpose:
    /// the richer <c>RuntimeTelemetryThrottle</c> lives in the UI assembly,
    /// which Infrastructure does not (and must not) reference.
    /// </summary>
    private sealed class RateLimiter
    {
        private readonly int _max;
        private readonly long _windowTicks;
        private readonly object _lock = new();
        private long _windowStart;
        private int _count;

        public RateLimiter(int maxPerWindow, TimeSpan window)
        {
            _max = maxPerWindow;
            _windowTicks = window.Ticks;
            _windowStart = DateTime.UtcNow.Ticks;
        }

        public bool TryAcquire()
        {
            long now = DateTime.UtcNow.Ticks;
            lock (_lock)
            {
                if (now - _windowStart >= _windowTicks)
                {
                    _windowStart = now;
                    _count = 0;
                }

                if (_count >= _max) return false;
                _count++;
                return true;
            }
        }
    }
}
