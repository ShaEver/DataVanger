using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Updates;

/// <summary>
/// A versioned, signed update manifest describing a set of detection-content
/// packages (feeds, rules, reputation/threat metadata, configuration).
///
/// This is a pure DTO. It deliberately stores <see cref="PublishedUtc"/> as a
/// string so the canonical payload is byte-for-byte stable and does not depend
/// on DateTime formatting/timezone behavior across runtimes.
/// </summary>
public sealed class UpdateManifest
{
    public int SchemaVersion { get; init; } = 1;

    public string FeedId { get; init; } = string.Empty;

    /// <summary>Monotonic sequence number. Higher means newer.</summary>
    public long Sequence { get; init; }

    /// <summary>ISO-8601 UTC timestamp string (e.g. "2026-01-01T00:00:00Z").</summary>
    public string PublishedUtc { get; init; } = string.Empty;

    public string MinimumSupportedClientVersion { get; init; } = "0.0.0";

    public IReadOnlyList<UpdatePackageEntry> Packages { get; init; } = Array.Empty<UpdatePackageEntry>();

    /// <summary>Signature envelope. Null/empty means the manifest is unsigned.</summary>
    public UpdateManifestSignature? Signature { get; init; }
}
