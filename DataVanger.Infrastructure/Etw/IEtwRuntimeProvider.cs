using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Etw;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Contract for an ETW runtime telemetry provider introduced in
/// Phase 2 Step 05 (ETW Real Provider).
///
/// Implementations MUST:
///   - never require admin privileges to construct or to stop;
///   - never throw from <see cref="StartAsync"/> when the host is
///     unsupported (return a status change instead);
///   - honor cancellation during start, stop, and disposal;
///   - publish normalized events through an
///     <see cref="DataVanger.Shared.RuntimeEvents.IRuntimeEventPublisher"/>
///     and NOT directly into scanner, behavioral, UI, or quarantine
///     surfaces;
///   - degrade to a no-op when configuration disallows the real
///     backend.
///
/// Anti-FP guarantee:
///   This contract intentionally exposes no remediation surface. It
///   has no Quarantine, no Kill, no Block, no Confirm. ETW is
///   telemetry. Verdicts originate from the existing scan engine and
///   classification policy.
/// </summary>
public interface IEtwRuntimeProvider : IAsyncDisposable
{
    /// <summary>Friendly provider name. Useful in health, logs, and tests.</summary>
    string Name { get; }

    /// <summary>Current lifecycle / availability status.</summary>
    EtwProviderStatus Status { get; }

    /// <summary>Cheap, allocation-light snapshot of provider health. Never throws.</summary>
    EtwProviderHealth GetHealth();

    /// <summary>
    /// Start collection. Idempotent: a second call on an already-started
    /// provider must be a no-op. Failures become health-state changes,
    /// never crashes.
    /// </summary>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Stop collection. Idempotent. MUST NOT block indefinitely; MUST
    /// honor cancellation and complete in bounded time.
    /// </summary>
    Task StopAsync(CancellationToken cancellationToken = default);
}
