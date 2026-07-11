using System;
using System.Collections.Generic;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Deterministic, network-free transport that serves manifest and package
/// bytes from in-memory buffers. For tests and local development only.
/// </summary>
public sealed class InMemoryUpdateTransport : IUpdateTransport
{
    private readonly byte[]? _manifestBytes;
    private readonly Dictionary<string, byte[]> _packagesByPath;

    public InMemoryUpdateTransport(byte[]? manifestBytes, IReadOnlyDictionary<string, byte[]>? packagesByRelativePath = null)
    {
        _manifestBytes = manifestBytes;
        _packagesByPath = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (packagesByRelativePath is not null)
        {
            foreach (var pair in packagesByRelativePath)
                _packagesByPath[Normalize(pair.Key)] = pair.Value;
        }
    }

    public byte[]? GetManifestBytes() => _manifestBytes;

    public byte[]? GetPackageBytes(UpdatePackageEntry entry)
    {
        if (entry is null) return null;
        return _packagesByPath.TryGetValue(Normalize(entry.RelativePath), out var bytes) ? bytes : null;
    }

    private static string Normalize(string? path)
        => (path ?? string.Empty).Replace('\\', '/').Trim();
}
