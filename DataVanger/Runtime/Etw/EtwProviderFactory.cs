using System;

namespace DataVanger.Runtime.Etw;

/// <summary>
/// Factory entry point for ETW providers.
///
/// The factory checks whether a real ETW backend can be created in the
/// current environment. Today the project does NOT ship a real ETW
/// backend (admin-only, would require Microsoft.Diagnostics.Tracing or a
/// native ETW session helper), so the factory always returns
/// <see cref="NullEtwProvider"/>. Callers that want deterministic event
/// injection (tests, future cloud replay) can pass
/// <see cref="EtwProviderMode.InMemory"/> to get an
/// <see cref="InMemoryEtwProvider"/>.
///
/// When a real provider is added later, only this factory needs to
/// change — the runtime pipeline already speaks the right interface.
/// </summary>
public static class EtwProviderFactory
{
    public static IEtwTelemetryProvider Create(EtwProviderMode mode = EtwProviderMode.Auto)
    {
        switch (mode)
        {
            case EtwProviderMode.InMemory:
                return new InMemoryEtwProvider();

            case EtwProviderMode.Null:
                return new NullEtwProvider();

            case EtwProviderMode.Auto:
            default:
                // No real ETW backend wired up in this build. We fail closed.
                return new NullEtwProvider();
        }
    }

    /// <summary>True when the current process could plausibly host a real ETW session.</summary>
    public static bool CanHostRealProvider()
    {
        // Conservative: only Windows even has ETW. Real subscription further
        // requires admin and a working diagnostics package, neither of which
        // we want to detect aggressively (the wrong probe would itself fail
        // closed). Return false today; revisit when a real provider lands.
        return OperatingSystem.IsWindows();
    }
}

public enum EtwProviderMode
{
    /// <summary>Pick the safest provider the environment can support.</summary>
    Auto = 0,

    /// <summary>Always return the no-op provider.</summary>
    Null,

    /// <summary>Return an in-memory mock for tests and replay.</summary>
    InMemory,
}
