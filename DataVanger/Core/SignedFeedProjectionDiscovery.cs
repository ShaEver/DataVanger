using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace DataVanger.Core;

/// <summary>Reads only complete, hash-verified immutable signed-feed versions.</summary>
public static class SignedFeedProjectionDiscovery
{
    public const string TransactionRootName = ".signed-feed";

    public static IReadOnlyList<string> GetVerifiedActiveVersionRoots(string signatureRoot)
    {
        var result = new List<string>();
        string transactionRoot = Path.Combine(Path.GetFullPath(signatureRoot), TransactionRootName);
        if (!Directory.Exists(transactionRoot)) return result;
        foreach (string feedRoot in Directory.EnumerateDirectories(transactionRoot))
        {
            try
            {
                var pointer = JsonSerializer.Deserialize<Pointer>(File.ReadAllText(Path.Combine(feedRoot, "active.json")));
                if (pointer is null || string.IsNullOrWhiteSpace(pointer.Version)) continue;
                string versions = Path.GetFullPath(Path.Combine(feedRoot, "versions"));
                string version = Path.GetFullPath(Path.Combine(versions, pointer.Version));
                if (!version.StartsWith(versions + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue;
                var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(Path.Combine(version, "version.json")));
                if (manifest is null || manifest.SchemaVersion != 1 || manifest.Sequence != pointer.Sequence ||
                    !string.Equals(manifest.CanonicalManifestSha256, pointer.CanonicalManifestSha256, StringComparison.OrdinalIgnoreCase) ||
                    manifest.Files.Count > 10_000) continue;
                bool valid = manifest.Files.All(f => VerifyFile(version, f));
                if (valid) result.Add(version);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or CryptographicException)
            {
                // A corrupt pointer/version is ignored as a whole; never load a partial set.
            }
        }
        return result;
    }

    private static bool VerifyFile(string root, Digest file)
    {
        if (string.IsNullOrWhiteSpace(file.RelativePath) || file.RelativePath.Contains("..", StringComparison.Ordinal) || Path.IsPathRooted(file.RelativePath)) return false;
        string path = Path.GetFullPath(Path.Combine(root, file.RelativePath));
        if (!path.StartsWith(Path.GetFullPath(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return false;
        var info = new FileInfo(path);
        if (!info.Exists || info.Length != file.Length) return false;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        string hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        return string.Equals(hash, file.Sha256, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class Pointer { public string Version { get; set; } = ""; public long Sequence { get; set; } public string CanonicalManifestSha256 { get; set; } = ""; }
    private sealed class Manifest { public int SchemaVersion { get; set; } public long Sequence { get; set; } public string CanonicalManifestSha256 { get; set; } = ""; public List<Digest> Files { get; set; } = new(); }
    private sealed class Digest { public string RelativePath { get; set; } = ""; public long Length { get; set; } public string Sha256 { get; set; } = ""; }
}
