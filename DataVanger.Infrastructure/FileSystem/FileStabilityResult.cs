using System;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Outcome of a file stability probe. Encodes both the observation
/// (length, last-write timestamp) and the disposition the orchestrator
/// should adopt — without ever implying a malware verdict.
/// </summary>
public enum FileStabilityOutcome
{
    /// <summary>File is readable, size+timestamp stable across samples.</summary>
    Stable,

    /// <summary>File no longer exists (deleted or never present).</summary>
    NotFound,

    /// <summary>Path resolves to a directory, not a file.</summary>
    IsDirectory,

    /// <summary>File size exceeds the configured real-time scan size cap.</summary>
    TooLarge,

    /// <summary>File could not be opened for read within the timeout (locked / still writing).</summary>
    Locked,

    /// <summary>Other I/O failure — surfaced as a warning, never as malware.</summary>
    Unavailable
}

public sealed class FileStabilityResult
{
    public FileStabilityOutcome Outcome { get; init; }
    public long Length { get; init; } = -1;
    public DateTimeOffset? LastWriteUtc { get; init; }
    public string? Reason { get; init; }

    public bool IsStable => Outcome == FileStabilityOutcome.Stable;
}
