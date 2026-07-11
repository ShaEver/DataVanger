using System;
using System.Collections.Generic;
using DataVanger.Shared.Realtime;

namespace DataVanger.Service.Realtime;

/// <summary>
/// Bounded scan queue with path-level coalescing.
///
/// Behavior:
///   - Bounded by <c>maxLength</c>; <see cref="TryEnqueue"/> returns
///     false on overflow instead of throwing — the orchestrator
///     surfaces overflow as a warning event.
///   - Duplicate pending paths are coalesced (latest request wins);
///     the queue depth does not grow with rapid event bursts.
///   - <see cref="TryDequeue"/> is non-blocking and cancellation-safe.
///   - Clear/Drain are deterministic for shutdown.
///
/// The queue is intentionally synchronous and tick-driven: the
/// orchestrator owns the worker lifecycle. No background threads are
/// started here.
/// </summary>
public sealed class RealtimeScanQueue
{
    private readonly object _gate = new();
    private readonly LinkedList<RealtimeScanRequest> _order = new();
    private readonly Dictionary<string, LinkedListNode<RealtimeScanRequest>> _byPath
        = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _maxLength;

    public RealtimeScanQueue(int maxLength)
    {
        if (maxLength <= 0) throw new ArgumentOutOfRangeException(nameof(maxLength));
        _maxLength = maxLength;
    }

    public int Count
    {
        get { lock (_gate) return _byPath.Count; }
    }

    public int Capacity => _maxLength;

    public bool TryEnqueue(RealtimeScanRequest request)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Path)) return false;
        lock (_gate)
        {
            if (_byPath.TryGetValue(request.Path, out var existing))
            {
                // Coalesce: replace the older request with the newer
                // observation so length/last-write/hash stay current.
                _order.Remove(existing);
                existing.Value = request;
                _order.AddLast(existing);
                _byPath[request.Path] = existing;
                return true;
            }

            if (_byPath.Count >= _maxLength) return false;

            var node = _order.AddLast(request);
            _byPath[request.Path] = node;
            return true;
        }
    }

    public bool TryDequeue(out RealtimeScanRequest? request)
    {
        lock (_gate)
        {
            var node = _order.First;
            if (node is null) { request = null; return false; }
            _order.RemoveFirst();
            _byPath.Remove(node.Value.Path);
            request = node.Value;
            return true;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _order.Clear();
            _byPath.Clear();
        }
    }
}
