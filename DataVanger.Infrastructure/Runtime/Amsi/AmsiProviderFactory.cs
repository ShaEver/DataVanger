using System;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Factory entry point for AMSI providers.
///
/// This build does not link <c>amsi.dll</c> directly — doing so would
/// add a hard Windows-only native dependency and require admin
/// elevation to register as an AMSI provider. Instead the factory
/// returns a content-analysis provider that runs the same heuristics
/// AMSI would feed us, just driven by explicit <c>SubmitContent</c>
/// calls from upstream monitors. A future PR can plug a real provider
/// here without touching the bridge or the behavioral engine.
/// </summary>
public static class AmsiProviderFactory
{
    public static IAmsiTelemetryProvider Create(AmsiProviderMode mode = AmsiProviderMode.Auto)
    {
        switch (mode)
        {
            case AmsiProviderMode.InMemory:
                return new InMemoryAmsiProvider();

            case AmsiProviderMode.Null:
                return new NullAmsiProvider();

            case AmsiProviderMode.Auto:
            default:
                // We cannot register as a real AMSI provider yet, but the
                // in-memory analyzer gives us bypass/content visibility for
                // anything callers feed to SubmitContent. Fail-soft.
                return new InMemoryAmsiProvider();
        }
    }

    public static bool CanHostRealProvider()
    {
        // A real AMSI provider would need to be registered via amsi.dll
        // and would only work on Windows. We don't probe further — see
        // the class comment.
        return OperatingSystem.IsWindows();
    }
}

public enum AmsiProviderMode
{
    /// <summary>Pick the safest provider the environment can support.</summary>
    Auto = 0,

    /// <summary>Always return the no-op provider.</summary>
    Null,

    /// <summary>Return the content-analysis in-memory provider.</summary>
    InMemory,
}
