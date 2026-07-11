using System;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Bounded options for <see cref="PipeIngestAmsiProvider"/>. Every value has a
/// safe default; nothing here opens a network port or requires admin to create
/// the listener (creating a named-pipe server is unprivileged).
/// </summary>
public sealed class PipeIngestOptions
{
    /// <summary>
    /// Production ingest pipe name. Distinct from the control pipe
    /// (<c>DataVanger.Service.Ipc</c>): the control pipe is Admin/SYSTEM-only,
    /// this one is connect+write for Authenticated Users because the native
    /// provider runs inside third-party processes of any local user.
    /// </summary>
    public const string DefaultPipeName = "DataVanger.Service.AmsiIngest";

    public string PipeName { get; init; } = DefaultPipeName;

    /// <summary>Concurrent server instances (bounded). A small number keeps the
    /// listener responsive without becoming a resource amplifier.</summary>
    public int MaxServerInstances { get; init; } = 2;

    /// <summary>Hard per-connection read deadline so a stalled/hostile client can
    /// never pin a server instance. Clamped to a small range.</summary>
    public TimeSpan ReadTimeout { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Rate-limit ceiling: messages accepted per <see cref="RateWindow"/>.
    /// Excess frames are dropped (no event) so a script loop cannot flood the bus.</summary>
    public int MaxMessagesPerWindow { get; init; } = 200;

    public TimeSpan RateWindow { get; init; } = TimeSpan.FromSeconds(1);

    public static PipeIngestOptions Default { get; } = new();
}
