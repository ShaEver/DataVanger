using System;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Factory entry point for AMSI providers.
///
/// The managed process never links or patches <c>amsi.dll</c>. The
/// default (<see cref="AmsiProviderMode.Auto"/>) returns a
/// content-analysis provider driven by explicit <c>SubmitContent</c>
/// calls. The opt-in <see cref="AmsiProviderMode.RealProvider"/> hosts
/// the write-only ingest pipe that receives observations from the
/// separately-registered native shim (<c>DataVanger.AmsiProvider.dll</c>)
/// — plugged in here without touching the bridge or the behavioral engine.
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

            case AmsiProviderMode.RealProvider:
                // Opt-in real-provider ingest path: host the write-only ingest
                // pipe that receives observations from the native amsi.dll shim.
                // Only meaningful where a listener can be hosted (Windows);
                // elsewhere degrade to the in-memory analyzer so callers keep a
                // working SubmitContent path and nothing crashes.
                return CanHostRealProvider()
                    ? new PipeIngestAmsiProvider()
                    : new InMemoryAmsiProvider();

            case AmsiProviderMode.Auto:
            default:
                // Auto never registers a real provider — the in-memory analyzer
                // gives bypass/content visibility for anything callers feed to
                // SubmitContent. Fail-soft.
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

    /// <summary>
    /// Host the real AMSI provider ingest endpoint (write-only named pipe fed by
    /// the native shim). Degrades to <see cref="InMemory"/> where a listener
    /// cannot be hosted. Opt-in and Windows-only.
    /// </summary>
    RealProvider,
}
