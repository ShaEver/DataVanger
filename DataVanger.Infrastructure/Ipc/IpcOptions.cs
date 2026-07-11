using System;
using System.Collections.Generic;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Bounded, development-safe options for the IPC transports. All values have
/// safe defaults: a small message cap, a short request timeout, and a
/// product-specific local pipe name. None of these settings open a network
/// port or require admin privileges.
/// </summary>
public sealed class IpcOptions
{
    /// <summary>Default bounded message size: 64 KiB.</summary>
    public const int DefaultMaxMessageBytes = 64 * 1024;

    /// <summary>Hard ceiling so a misconfiguration cannot disable the bound.</summary>
    public const int AbsoluteMaxMessageBytes = 1024 * 1024;

    /// <summary>Product-specific, local-only pipe name.</summary>
    public const string DefaultPipeName = "DataVanger.Service.Ipc";

    private readonly int _maxMessageBytes = DefaultMaxMessageBytes;

    /// <summary>Maximum serialized envelope size. Clamped to a safe range.</summary>
    public int MaxMessageBytes
    {
        get => _maxMessageBytes;
        init => _maxMessageBytes = value < 256
            ? DefaultMaxMessageBytes
            : Math.Min(value, AbsoluteMaxMessageBytes);
    }

    /// <summary>Per-request timeout. Defaults to 5 seconds.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Local-only pipe name used by the named-pipe transport.</summary>
    public string PipeName { get; init; } = DefaultPipeName;

    /// <summary>Friendly client identifier carried on requests.</summary>
    public string ClientName { get; init; } = "DataVanger.UI";

    /// <summary>
    /// When true (default) and the host runs on Windows, the named-pipe host
    /// applies a least-privilege security descriptor restricting WHICH local
    /// principals may connect (see <see cref="IpcPipeSecurity"/>). On non-Windows
    /// hosts this is ignored and a plain local pipe is used (tests exercise the
    /// in-memory transport).
    ///
    /// This connection-level control is defense-in-depth ONLY. It never replaces
    /// payload validation: <see cref="IpcSecurityPolicy"/> (allowlist/size/path),
    /// <c>NamedPipeFraming</c> (bounded framing), and <c>IpcSerialization</c>
    /// (defensive deserialization) always remain active regardless of this flag.
    /// </summary>
    public bool HardenPipeAcl { get; init; } = true;

    /// <summary>
    /// Phase 02B fail-closed gate. When true, the named-pipe host REFUSES to
    /// create any pipe that is not ACL-hardened: if the platform does not
    /// support pipe security descriptors, or <see cref="HardenPipeAcl"/> was
    /// disabled, host creation throws instead of silently opening a plain
    /// (unrestricted) pipe. Production service composition must set this to
    /// true before any privileged command ships (phases 03/04); it defaults to
    /// false so existing test transports and non-Windows unit tests keep
    /// working unchanged.
    /// </summary>
    public bool RequireAclHardening { get; init; } = false;

    /// <summary>
    /// Additional local principals permitted to connect to the IPC pipe, beyond
    /// the creating user and the Local System account. Each entry may be an SDDL
    /// SID string (e.g. "S-1-5-...") or a local account name (e.g. "MACHINE\\user").
    /// Defaults to empty. Invalid/unresolvable entries are ignored and never
    /// broaden access. Everyone, Network, and Anonymous are never granted.
    /// </summary>
    public IReadOnlyList<string> AllowedPrincipalSids { get; init; } = Array.Empty<string>();

    public static IpcOptions Default { get; } = new();
}
