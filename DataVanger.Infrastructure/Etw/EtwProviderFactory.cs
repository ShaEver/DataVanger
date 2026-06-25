using System;
using DataVanger.Shared.Etw;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Safe-defaults factory for ETW runtime providers introduced in
/// Phase 2 Step 05 (ETW Real Provider).
///
/// The factory NEVER returns a Windows real provider unless every
/// gate is satisfied:
///   - configuration is non-null and <see cref="EtwProviderConfiguration.Enabled"/>;
///   - the host OS is Windows (or a custom platform probe says so);
///   - <see cref="EtwProviderConfiguration.AllowRealProvider"/> is true;
///   - we are not in development mode (unless
///     <see cref="EtwProviderConfiguration.ForceRealProviderInDevelopment"/>
///     is also true).
///
/// Otherwise the factory returns a Null provider. There is no path
/// through this factory that constructs a Windows real provider in a
/// test run or a non-Windows host.
/// </summary>
public static class EtwProviderFactory
{
    /// <summary>Always returns a Null provider. Safe in every environment.</summary>
    public static IEtwRuntimeProvider CreateNull(EtwProviderStatus initialStatus = EtwProviderStatus.Disabled)
        => new NullEtwRuntimeProvider(initialStatus);

    /// <summary>
    /// Returns an InMemory provider wired to <paramref name="publisher"/>.
    /// Used by tests and by future cross-platform replay scenarios.
    /// </summary>
    public static InMemoryEtwRuntimeProvider CreateInMemory(
        IRuntimeEventPublisher publisher,
        EtwProviderConfiguration? configuration = null)
    {
        if (publisher is null) throw new ArgumentNullException(nameof(publisher));
        return new InMemoryEtwRuntimeProvider(publisher, configuration);
    }

    /// <summary>
    /// Chooses the safest provider that satisfies the supplied
    /// configuration. Defaults aggressively to Null. Returns Windows
    /// real provider ONLY when every safety gate passes.
    /// </summary>
    public static IEtwRuntimeProvider Create(
        IRuntimeEventPublisher publisher,
        EtwProviderConfiguration? configuration = null,
        Func<bool>? platformProbeOverride = null)
    {
        if (publisher is null) throw new ArgumentNullException(nameof(publisher));

        var cfg = (configuration ?? EtwProviderConfiguration.DevelopmentSafe()).WithSafeDefaults();

        if (!cfg.Enabled)
        {
            return CreateNull(EtwProviderStatus.Disabled);
        }

        if (!IsPlatformSupported(platformProbeOverride))
        {
            return CreateNull(EtwProviderStatus.UnsupportedPlatform);
        }

        if (!cfg.AllowRealProvider)
        {
            return CreateNull(EtwProviderStatus.NotConfigured);
        }

        if (cfg.DevelopmentMode && !cfg.ForceRealProviderInDevelopment)
        {
            return CreateNull(EtwProviderStatus.NotConfigured);
        }

        return new WindowsEtwRuntimeProvider(publisher, cfg, platformProbeOverride);
    }

    private static bool IsPlatformSupported(Func<bool>? platformProbeOverride)
        => platformProbeOverride?.Invoke() ?? OperatingSystem.IsWindows();
}
