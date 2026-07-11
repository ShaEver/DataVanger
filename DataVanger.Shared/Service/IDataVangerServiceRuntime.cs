using System;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.Service;

/// <summary>
/// Contract for the DataVanger service runtime. Defined in the shared
/// project so the UI, tests, and future IPC layers can consume the
/// abstraction without taking a dependency on DataVanger.Service.
///
/// Implementations MUST:
///   - be idempotent under double Start / double Stop / Stop-before-Start
///   - never create persistent background loops that survive disposal
///   - never require admin privileges, never install a Windows Service,
///     never inject into other processes, never hook OS internals
///   - degrade gracefully when configuration is missing or malformed
/// </summary>
public interface IDataVangerServiceRuntime : IDisposable
{
    DataVangerRuntimeMode Mode { get; }

    DataVangerServiceState State { get; }

    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync(CancellationToken cancellationToken);

    DataVangerServiceStatus GetStatusSnapshot();
}
