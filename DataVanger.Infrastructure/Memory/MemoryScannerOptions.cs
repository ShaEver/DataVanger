using System;

namespace DataVanger.Memory;

/// <summary>
/// Knobs for the memory scanner. Defaults are conservative: the scanner
/// must not destabilise the host or freeze the UI.
/// </summary>
public sealed class MemoryScannerOptions
{
    /// <summary>If false the scanner short-circuits to a no-op result.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Cap on processes inspected per scan pass.</summary>
    public int MaxProcesses { get; set; } = 64;

    /// <summary>Cap on regions inspected per process.</summary>
    public int MaxRegionsPerProcess { get; set; } = 512;

    /// <summary>Hard ceiling on bytes read per region.</summary>
    public long MaxBytesPerRegion { get; set; } = 256 * 1024;

    /// <summary>Hard ceiling on total bytes read per scan pass.</summary>
    public long MaxTotalBytes { get; set; } = 16 * 1024 * 1024;

    /// <summary>Overall scan timeout. Zero = no timeout.</summary>
    public TimeSpan OverallTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Per-process timeout.</summary>
    public TimeSpan PerProcessTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Entropy threshold (0..8 Shannon bits/byte) for HighEntropy heuristics.</summary>
    public double HighEntropyThreshold { get; set; } = 7.5;

    /// <summary>Skip processes whose image is signed by a known-trusted publisher list.</summary>
    public bool SkipTrustedSignedProcesses { get; set; } = true;

    /// <summary>Skip protected/PPL processes by default (we can't read them anyway).</summary>
    public bool SkipProtectedProcesses { get; set; } = true;

    /// <summary>Maximum findings retained per scan to avoid unbounded growth.</summary>
    public int MaxFindings { get; set; } = 1024;
}
