using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Ipc;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Deterministic in-memory host wrapper used for tests and development. It
/// delegates to an inner host (the service command router) and can apply an
/// optional, cancellation-safe artificial delay so timeout behavior can be
/// exercised without real time-sensitivity or background loops.
///
/// It does NOT start any thread, timer, or loop. It is a pass-through.
/// </summary>
public sealed class InMemoryDataVangerServiceHost : IDataVangerServiceHost
{
    private readonly IDataVangerServiceHost _inner;
    private readonly TimeSpan _artificialDelay;

    public InMemoryDataVangerServiceHost(IDataVangerServiceHost inner, TimeSpan? artificialDelay = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _artificialDelay = artificialDelay.GetValueOrDefault(TimeSpan.Zero);
    }

    public async Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken = default)
    {
        if (_artificialDelay > TimeSpan.Zero)
        {
            // Cancellation-safe: a cancelled / timed-out token aborts the delay.
            await Task.Delay(_artificialDelay, cancellationToken).ConfigureAwait(false);
        }

        return await _inner.HandleAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
