using System;

namespace DataVanger.Engine.Remediation.Files;

/// <summary>
/// A typed file hash value. Equality is case-insensitive on the hex digest so a
/// hash comparison cannot fail merely on letter casing. Algorithm defaults to
/// SHA-256 to match the rest of DataVanger.
/// </summary>
public readonly record struct FileHashValue
{
    public FileHashValue(string hexDigest, string algorithm = "SHA-256")
    {
        if (string.IsNullOrWhiteSpace(hexDigest))
            throw new ArgumentException("Hash digest must be non-empty.", nameof(hexDigest));
        HexDigest = hexDigest.Trim();
        Algorithm = string.IsNullOrWhiteSpace(algorithm) ? "SHA-256" : algorithm.Trim();
    }

    public string HexDigest { get; }
    public string Algorithm { get; }

    public bool Matches(FileHashValue other)
        => string.Equals(Algorithm, other.Algorithm, StringComparison.OrdinalIgnoreCase)
           && string.Equals(HexDigest, other.HexDigest, StringComparison.OrdinalIgnoreCase);

    public override string ToString() => $"{Algorithm}:{HexDigest}";
}

/// <summary>Computes the hash of a file on disk. Abstracted so the file
/// remediation flow can be exercised by fakes without touching the disk, and so
/// the real implementation is the only thing that opens file streams for hashing.</summary>
public interface IFileHashProvider
{
    System.Threading.Tasks.Task<FileHashValue> ComputeAsync(string path, System.Threading.CancellationToken cancellationToken = default);
}

/// <summary>
/// The ONLY abstraction that performs real filesystem mutations for remediation
/// (existence probe, reparse detection, delete). Centralising it means the
/// destructive-API audit has exactly one place to inspect, and tests can fake it
/// to prove no delete happens on a blocked path.
/// </summary>
public interface IFileSystemRemediationOperations
{
    bool Exists(string path);

    /// <summary>True if the path is a reparse point (symlink/junction). Used to
    /// refuse acting through a redirection into a protected location.</summary>
    bool IsReparsePoint(string path);

    /// <summary>Deletes the original file at <paramref name="path"/>. Called ONLY
    /// after every quarantine/hash/safe-path gate has passed.</summary>
    void DeleteOriginal(string path);
}
