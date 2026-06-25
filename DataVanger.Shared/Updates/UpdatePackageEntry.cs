using System;

namespace DataVanger.Shared.Updates;

/// <summary>
/// One package entry inside a signed <see cref="UpdateManifest"/>. This is a
/// pure DTO; it carries no content bytes (those are fetched via a transport
/// and validated against <see cref="Sha256"/> / <see cref="SizeBytes"/>).
/// </summary>
public sealed class UpdatePackageEntry
{
    /// <summary>Stable logical id of the package (e.g. "hash-blacklist").</summary>
    public string Id { get; init; } = string.Empty;

    public UpdatePackageKind Kind { get; init; } = UpdatePackageKind.Unknown;

    public string Version { get; init; } = string.Empty;

    /// <summary>Lower-case hex SHA-256 of the authenticated package content.</summary>
    public string Sha256 { get; init; } = string.Empty;

    public long SizeBytes { get; init; }

    /// <summary>
    /// Path of the package relative to the update staging root. MUST NOT be
    /// absolute, contain "..", a drive letter, or a UNC prefix. Validated by
    /// the package verifier before fetch/apply.
    /// </summary>
    public string RelativePath { get; init; } = string.Empty;

    /// <summary>
    /// When true, the whole update aborts if this package fails validation.
    /// Optional packages may fail without aborting, subject to policy.
    /// </summary>
    public bool Required { get; init; }
}
