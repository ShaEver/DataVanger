using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Service;

/// <summary>
/// Result of attempting to load a <see cref="DataVangerServiceConfiguration"/>
/// from disk or another source. The loader NEVER throws on missing /
/// malformed input — it returns this result with warnings and safe
/// defaults so the runtime can keep starting in a degraded state.
/// </summary>
public sealed class ServiceConfigurationLoadResult
{
    public ServiceConfigurationLoadResult(
        DataVangerServiceConfiguration configuration,
        bool loadedFromSource,
        IReadOnlyList<string> warnings)
    {
        Configuration = configuration
            ?? throw new ArgumentNullException(nameof(configuration));
        LoadedFromSource = loadedFromSource;
        Warnings = warnings ?? Array.Empty<string>();
    }

    public DataVangerServiceConfiguration Configuration { get; }

    /// <summary>
    /// True only when the configuration was successfully parsed from the
    /// requested source. False means safe defaults are in effect.
    /// </summary>
    public bool LoadedFromSource { get; }

    public IReadOnlyList<string> Warnings { get; }

    public bool HasWarnings => Warnings.Count > 0;
}
