using System;
using System.IO;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Local file-system transport. Reads the manifest and packages from a root
/// directory. NO network access of any kind. As defense in depth it re-checks
/// each package's relative path for traversal and refuses to read outside its
/// root, returning null for anything unsafe or missing.
/// </summary>
public sealed class FileUpdateTransport : IUpdateTransport
{
    private readonly string _rootDirectory;
    private readonly string _manifestFileName;

    public FileUpdateTransport(string rootDirectory, string manifestFileName = "manifest.json")
    {
        if (string.IsNullOrWhiteSpace(rootDirectory)) throw new ArgumentException("Root directory is required.", nameof(rootDirectory));
        if (string.IsNullOrWhiteSpace(manifestFileName)) throw new ArgumentException("Manifest file name is required.", nameof(manifestFileName));
        _rootDirectory = Path.GetFullPath(rootDirectory);
        _manifestFileName = manifestFileName;
    }

    public byte[]? GetManifestBytes()
    {
        var path = Path.Combine(_rootDirectory, _manifestFileName);
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    public byte[]? GetPackageBytes(UpdatePackageEntry entry)
    {
        if (entry is null) return null;
        if (!UpdatePackageVerifier.IsSafeRelativePath(entry.RelativePath)) return null;

        var combined = Path.GetFullPath(Path.Combine(_rootDirectory, entry.RelativePath));

        // Defense in depth: never read outside the configured root.
        var rootPrefix = _rootDirectory.EndsWith(Path.DirectorySeparatorChar)
            ? _rootDirectory
            : _rootDirectory + Path.DirectorySeparatorChar;
        if (!combined.StartsWith(rootPrefix, StringComparison.Ordinal)) return null;

        return File.Exists(combined) ? File.ReadAllBytes(combined) : null;
    }
}
