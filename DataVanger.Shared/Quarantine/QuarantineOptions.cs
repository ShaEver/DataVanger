using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Configuration for the Secure Quarantine V2 service. Defaults are
/// conservative and development-safe: nothing is deleted unless a request
/// explicitly asks for it and policy allows it, and restore is refused into
/// the quarantine store internals or any configured protected root.
/// </summary>
public sealed class QuarantineOptions
{
    /// <summary>
    /// When true (the default for tests/dev), the service never deletes or
    /// neutralizes original source files even if a request asks to — it stores
    /// the encrypted copy and reports the original as retained. This keeps the
    /// build/test environment safe.
    /// </summary>
    public bool DevelopmentMode { get; set; } = true;

    /// <summary>
    /// Master switch for original deletion. Even in production, deletion only
    /// happens when both this is true AND the individual request opts in.
    /// </summary>
    public bool AllowOriginalDeletion { get; set; }

    /// <summary>Upper bound on payload size accepted into quarantine. 0 = unlimited.</summary>
    public long MaxPayloadBytes { get; set; } = 256L * 1024 * 1024;

    /// <summary>
    /// Temporary hard ceiling for the current single-chunk AES-GCM format. Until a
    /// versioned chunked format is introduced, production never holds more than this
    /// amount of plaintext (plus one ciphertext) in memory.
    /// </summary>
    public long MaxInMemoryPayloadBytes { get; set; } = 16L * 1024 * 1024;

    /// <summary>
    /// Absolute roots that restore must NEVER write into (quarantine store,
    /// program/runtime directories). The quarantine root is always implicitly
    /// forbidden in addition to these.
    /// </summary>
    public List<string> ForbiddenRestoreRoots { get; set; } = new();

    public QuarantineOptions Clone()
    {
        return new QuarantineOptions
        {
            DevelopmentMode = DevelopmentMode,
            AllowOriginalDeletion = AllowOriginalDeletion,
            MaxPayloadBytes = MaxPayloadBytes,
            MaxInMemoryPayloadBytes = MaxInMemoryPayloadBytes,
            ForbiddenRestoreRoots = new List<string>(ForbiddenRestoreRoots),
        };
    }

    /// <summary>Development-safe defaults: never deletes originals, forbids unsafe restore roots.</summary>
    public static QuarantineOptions DevelopmentSafe() => new();

    /// <summary>
    /// Production defaults: original deletion is permitted (still requires the
    /// per-request opt-in), and development protections are off.
    /// </summary>
    public static QuarantineOptions Production() => new()
    {
        DevelopmentMode = false,
        AllowOriginalDeletion = true,
    };
}
