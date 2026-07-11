using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Engine.Remediation.Files;

/// <summary>Real SHA-256 hashing over a file stream. The only place file bytes
/// are read for remediation hashing.</summary>
public sealed class Sha256FileHashProvider : IFileHashProvider
{
    public async Task<FileHashValue> ComputeAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sha = SHA256.Create();
        byte[] digest = await sha.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
        return new FileHashValue(Convert.ToHexString(digest).ToLowerInvariant(), "SHA-256");
    }
}

/// <summary>
/// Real filesystem operations for remediation. The single concrete place that
/// performs an original-file delete. Every caller path reaches it only after the
/// quarantine/hash/safe-path gates in <see cref="FileRemediationService"/>.
/// </summary>
public sealed class SystemFileRemediationOperations : IFileSystemRemediationOperations
{
    public bool Exists(string path) => File.Exists(path);

    public bool IsReparsePoint(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint);
        }
        catch (Exception)
        {
            // If attributes cannot be read, fail safe: treat as a reparse point so
            // the caller refuses to act on an opaque/ambiguous path.
            return true;
        }
    }

    public void DeleteOriginal(string path) => File.Delete(path);
}
