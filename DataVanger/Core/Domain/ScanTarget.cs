using System;
using System.IO;

namespace DataVanger.Core.Domain;

/// <summary>
/// Represents a single file/object being analyzed by the scan pipeline.
///
/// A <see cref="ScanTarget"/> is built once for each eligible file during target
/// discovery. It accumulates classification-relevant facts (hash, signature,
/// trust state) as the pipeline progresses, so detection modules see consistent,
/// pre-computed context instead of recomputing it themselves.
///
/// Modules MUST NOT mutate <see cref="FileInfo"/> or perform side effects.
/// They should only read this object and return <see cref="Evidence"/>.
/// </summary>
public sealed class ScanTarget
{
    public ScanTarget(FileInfo file)
    {
        File = file ?? throw new ArgumentNullException(nameof(file));
        FullPath = file.FullName;
        FullPathLower = FullPath.ToLowerInvariant();
        FileName = file.Name;
        FileNameLower = FileName.ToLowerInvariant();
        Extension = file.Extension.ToLowerInvariant();
    }

    public FileInfo File { get; }
    public string FullPath { get; }
    public string FullPathLower { get; }
    public string FileName { get; }
    public string FileNameLower { get; }
    public string Extension { get; }

    /// <summary>SHA-256 in upper-case hex once computed by the hashing stage.</summary>
    public string? Sha256 { get; set; }

    /// <summary>Hash status from the signature database (set by the hash module).</summary>
    public FileTrustState TrustState { get; set; } = FileTrustState.Unknown;

    /// <summary>True when the file's hash was found in the local malware database.</summary>
    public bool IsKnownMalicious { get; set; }

    /// <summary>True when an Authenticode signature was verified successfully.</summary>
    public bool IsSigned { get; set; }

    /// <summary>Verified publisher subject, empty when unsigned or unknown.</summary>
    public string Publisher { get; set; } = "";

    /// <summary>True when the publisher is in the trusted publisher allowlist.</summary>
    public bool PublisherTrusted { get; set; }

    /// <summary>True when this file path was found in a Windows persistence location.</summary>
    public bool IsPersistenceCandidate { get; set; }

    /// <summary>True when the file is being executed at scan time.</summary>
    public bool IsRunning { get; set; }
}
