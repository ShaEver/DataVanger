using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Tracks outstanding work in the deep scan pipeline so the orchestrator can
/// close the work channel only when every produced item has been consumed.
///
/// Two events feed it: <see cref="Enqueued"/> when a producer (discovery or
/// archive expansion) writes an item, and <see cref="Completed"/> when a
/// worker finishes one. When both the counter hits zero AND discovery has
/// signalled "no more roots", the orchestrator wakes up via
/// <see cref="WaitForDrainAsync"/> and completes the channel.
///
/// Implemented with a single integer plus a re-armed
/// <see cref="TaskCompletionSource"/> so workers don't busy-wait.
/// </summary>
public sealed class PendingWorkCounter
{
    private int _pending;
    private int _discoveryDone;
    private TaskCompletionSource _idle = NewTcs();

    private static TaskCompletionSource NewTcs() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public int Pending => Volatile.Read(ref _pending);
    public bool DiscoveryFinished => Volatile.Read(ref _discoveryDone) == 1;

    public void Enqueued()
    {
        Interlocked.Increment(ref _pending);
    }

    public void Completed()
    {
        int updated = Interlocked.Decrement(ref _pending);
        if (updated == 0) SignalIdleIfDone();
    }

    public void MarkDiscoveryDone()
    {
        if (Interlocked.Exchange(ref _discoveryDone, 1) == 1) return;
        if (Volatile.Read(ref _pending) == 0) SignalIdleIfDone();
    }

    public Task WaitForDrainAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return Task.FromCanceled(cancellationToken);
        if (DiscoveryFinished && Pending == 0) return Task.CompletedTask;
        var task = Volatile.Read(ref _idle).Task;
        return cancellationToken.CanBeCanceled
            ? task.WaitAsync(cancellationToken)
            : task;
    }

    private void SignalIdleIfDone()
    {
        if (!DiscoveryFinished) return;
        var snapshot = Volatile.Read(ref _idle);
        snapshot.TrySetResult();
    }
}
