using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Etw;
using DataVanger.Shared.Etw;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Service.Runtime;

/// <summary>
/// Service-level composition helper introduced in Phase 2 Step 05
/// (ETW Real Provider). Lets the service host pick an
/// <see cref="IEtwRuntimeProvider"/> through a single safe entry point
/// and bind it to the runtime event pipeline.
///
/// This host is wiring only — it never owns ETW sessions, never
/// loads drivers, never elevates privileges, and never carries any
/// remediation authority.
/// </summary>
public static class EtwRuntimeProviderHost
{
    /// <summary>
    /// Build an ETW provider that publishes into <paramref name="publisher"/>.
    /// Defaults to a Null provider when configuration / platform gates
    /// disallow the real backend, matching
    /// <see cref="EtwProviderFactory.Create"/> behavior.
    /// </summary>
    public static IEtwRuntimeProvider CreateProvider(
        IRuntimeEventPublisher publisher,
        EtwProviderConfiguration? configuration = null,
        Func<bool>? platformProbeOverride = null)
    {
        if (publisher is null) throw new ArgumentNullException(nameof(publisher));
        return EtwProviderFactory.Create(publisher, configuration, platformProbeOverride);
    }

    /// <summary>
    /// Convenience: build an InMemory provider for service-side smoke
    /// tests that want to exercise the publisher without touching the
    /// OS. Never used for production ETW collection.
    /// </summary>
    public static InMemoryEtwRuntimeProvider CreateInMemoryProvider(
        IRuntimeEventPublisher publisher,
        EtwProviderConfiguration? configuration = null)
    {
        if (publisher is null) throw new ArgumentNullException(nameof(publisher));
        return EtwProviderFactory.CreateInMemory(publisher, configuration);
    }

    /// <summary>
    /// Cooperative start. Catches and discards any unexpected exception
    /// so a provider failure cannot crash the service host. The
    /// provider already promises StartAsync never throws on
    /// unsupported environments; this is belt-and-braces for future
    /// implementations.
    /// </summary>
    public static async Task<EtwProviderStatus> SafeStartAsync(IEtwRuntimeProvider provider, CancellationToken cancellationToken = default)
    {
        if (provider is null) throw new ArgumentNullException(nameof(provider));
        try
        {
            await provider.StartAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Cooperative — return current status unchanged.
        }
        catch
        {
            // Defensive — never crash the host.
        }
        return provider.Status;
    }

    /// <summary>
    /// Cooperative stop + dispose. Never throws. Idempotent in
    /// combination with the provider's own Stop/Dispose contracts.
    /// </summary>
    public static async Task SafeStopAsync(IEtwRuntimeProvider provider, CancellationToken cancellationToken = default)
    {
        if (provider is null) return;
        try { await provider.StopAsync(cancellationToken).ConfigureAwait(false); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        try { await provider.DisposeAsync().ConfigureAwait(false); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
    }
}
