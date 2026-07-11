using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Behavioral;

/// <summary>
/// In-memory pub/sub bus for behavioral events.
///
/// Design:
///   - Publisher writes to a bounded <see cref="ConcurrentQueue{T}"/>.
///     When the queue is full, the OLDEST event is dropped — never the
///     incoming one. This keeps recent telemetry, which is more valuable
///     for correlation than historic noise.
///   - A single background worker drains the queue and fans out to
///     subscribers. Subscriber exceptions are swallowed (logged via the
///     diagnostic callback if provided) so one bad handler can never
///     poison the bus.
///   - <see cref="Dispose"/> stops the worker cleanly.
///
/// The bus is designed for stability under long runtime; it never holds
/// more than <see cref="Capacity"/> events in memory and never spawns
/// per-event threads.
/// </summary>
public sealed class BehavioralEventBus : IBehavioralEventBus, IDisposable
{
    private readonly ConcurrentQueue<BehavioralEvent> _queue = new();
    private readonly ConcurrentDictionary<Guid, Action<BehavioralEvent>> _subscribers = new();
    private readonly SemaphoreSlim _signal = new(0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;
    private readonly Action<string>? _diagnostics;
    // Serialises Dispatch between the background worker and DrainNow so events
    // are always dispatched in FIFO order regardless of which path drains them.
    private readonly object _dispatchLock = new();
    private long _published;
    private long _dropped;
    private int _approxQueueSize;

    public int Capacity { get; }
    public long PublishedCount => Interlocked.Read(ref _published);
    public long DroppedCount => Interlocked.Read(ref _dropped);
    public int CurrentQueueSize => Volatile.Read(ref _approxQueueSize);
    public int SubscriberCount => _subscribers.Count;

    public BehavioralEventBus(int capacity = 4096, Action<string>? diagnostics = null)
    {
        Capacity = capacity > 0 ? capacity : 4096;
        _diagnostics = diagnostics;
        _worker = Task.Run(WorkerLoop);
    }

    public bool Publish(BehavioralEvent ev)
    {
        if (ev is null) return false;
        if (_cts.IsCancellationRequested) return false;

        // Enforce capacity: drop oldest while over-capacity. Done in a tight
        // loop because the queue is concurrent and other publishers may also
        // be enqueuing — but we never block on a full queue.
        while (Volatile.Read(ref _approxQueueSize) >= Capacity)
        {
            if (_queue.TryDequeue(out _))
            {
                Interlocked.Decrement(ref _approxQueueSize);
                Interlocked.Increment(ref _dropped);
            }
            else
            {
                break;
            }
        }

        _queue.Enqueue(ev);
        Interlocked.Increment(ref _approxQueueSize);
        Interlocked.Increment(ref _published);
        try { _signal.Release(); } catch (SemaphoreFullException) { /* worker is keeping up */ }
        return true;
    }

    public IDisposable Subscribe(Action<BehavioralEvent> handler)
    {
        if (handler is null) throw new ArgumentNullException(nameof(handler));
        var id = Guid.NewGuid();
        _subscribers[id] = handler;
        return new Subscription(this, id);
    }

    private async Task WorkerLoop()
    {
        var token = _cts.Token;
        while (!token.IsCancellationRequested)
        {
            try
            {
                await _signal.WaitAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            // Drain under the dispatch lock so DrainNow and the worker never
            // dispatch events out of order.
            lock (_dispatchLock)
            {
                int drained = 0;
                while (drained < 256 && _queue.TryDequeue(out var ev))
                {
                    Interlocked.Decrement(ref _approxQueueSize);
                    drained++;
                    Dispatch(ev);
                }
            }
        }
    }

    private void Dispatch(BehavioralEvent ev)
    {
        // Snapshot subscribers — avoid concurrent modification during iteration.
        foreach (var kvp in _subscribers)
        {
            try
            {
                kvp.Value(ev);
            }
            catch (Exception ex)
            {
                try { _diagnostics?.Invoke($"behavioral handler exception: {ex.GetType().Name}: {ex.Message}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
            }
        }
    }

    /// <summary>
    /// Synchronously drain currently queued events to subscribers. Useful in
    /// tests where we want deterministic ordering instead of waiting on the
    /// background worker.
    /// </summary>
    public int DrainNow()
    {
        int drained = 0;
        lock (_dispatchLock)
        {
            while (_queue.TryDequeue(out var ev))
            {
                Interlocked.Decrement(ref _approxQueueSize);
                drained++;
                Dispatch(ev);
                // Consume the matching signal token so the worker doesn't spin
                // through an empty queue once we hand control back.
                try { _signal.Wait(0); } catch (Exception) { /* Best-effort signal-token drain - swallow intentionally. */ }
            }
        }
        return drained;
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        try { _signal.Release(); } catch (SemaphoreFullException) { }
        try { _worker.Wait(TimeSpan.FromSeconds(2)); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        _cts.Dispose();
        _signal.Dispose();
    }

    private sealed class Subscription : IDisposable
    {
        private readonly BehavioralEventBus _bus;
        private readonly Guid _id;
        private int _disposed;
        public Subscription(BehavioralEventBus bus, Guid id) { _bus = bus; _id = id; }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                _bus._subscribers.TryRemove(_id, out _);
        }
    }
}
