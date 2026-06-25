using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Realtime;

namespace DataVanger.Service.Realtime;

/// <summary>
/// Lifecycle and observability surface for the real-time file
/// protection orchestrator.
///
/// Contract:
///   - StartAsync / StopAsync are idempotent and never throw.
///   - When <see cref="RealtimeProtectionOptions.Enabled"/> is false,
///     StartAsync starts no watchers and the runtime stays in the
///     <c>Disabled</c> state.
///   - GetStatusSnapshot is safe to call at any moment.
///   - The orchestrator NEVER claims to be active protection unless
///     watchers are actually running.
/// </summary>
public interface IRealtimeProtectionService : IDisposable
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    RealtimeProtectionStatus GetStatusSnapshot();
}
