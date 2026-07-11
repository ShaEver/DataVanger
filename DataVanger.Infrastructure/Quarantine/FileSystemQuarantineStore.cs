using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Infrastructure.Quarantine;

/// <summary>
/// Filesystem-backed quarantine store (Secure Quarantine V2).
///
/// Layout under the configured root:
///   records/  &lt;quarantine-id&gt;.json   (authenticated record envelope)
///   payloads/ &lt;quarantine-id&gt;.qbin   (authenticated-encrypted payload)
///   temp/     &lt;...&gt;.tmp               (staging for atomic commit)
///
/// Every write stages into temp/ and is then atomically moved into its final
/// location, so a crash mid-write never leaves a partial record or payload.
/// The store never decrypts, never deletes originals, and never classifies.
/// </summary>
public sealed class FileSystemQuarantineStore : IQuarantineStore
{
    private const long MaxEncodedPayloadBytes = 32L * 1024 * 1024;
    private readonly string _recordsDir;
    private readonly string _payloadsDir;
    private readonly string _tempDir;

    public FileSystemQuarantineStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Quarantine root is required.", nameof(root));
        Root = Path.GetFullPath(root);
        EnsureNoReparseAncestors(Root);
        _recordsDir = Path.Combine(Root, "records");
        _payloadsDir = Path.Combine(Root, "payloads");
        _tempDir = Path.Combine(Root, "temp");
        Directory.CreateDirectory(_recordsDir);
        Directory.CreateDirectory(_payloadsDir);
        Directory.CreateDirectory(_tempDir);
        EnsureNoReparseAncestors(_recordsDir);
        EnsureNoReparseAncestors(_payloadsDir);
        EnsureNoReparseAncestors(_tempDir);
    }

    public string Root { get; }

    public async Task WritePayloadAsync(string payloadName, QuarantineEncryptedPayload payload, CancellationToken cancellationToken = default)
    {
        var encoded = QuarantinePayloadCodec.Encode(payload);
        var finalPath = Path.Combine(_payloadsDir, SafeLeaf(payloadName));
        await WriteAtomicAsync(finalPath, encoded, cancellationToken).ConfigureAwait(false);
    }

    public async Task<QuarantineEncryptedPayload?> ReadPayloadAsync(string payloadName, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(_payloadsDir, SafeLeaf(payloadName));
        EnsureNoReparseAncestors(path);
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > MaxEncodedPayloadBytes) return null;
        var raw = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return QuarantinePayloadCodec.TryDecode(raw, "AES-256-GCM");
    }

    public Task<bool> PayloadExistsAsync(string payloadName, CancellationToken cancellationToken = default)
    {
        string path = Path.Combine(_payloadsDir, SafeLeaf(payloadName));
        EnsureNoReparseAncestors(path);
        return Task.FromResult(File.Exists(path));
    }

    public async Task WriteRecordAsync(QuarantineRecord record, byte[] canonicalMetadata, byte[] metadataTag, CancellationToken cancellationToken = default)
    {
        var envelope = QuarantineRecordEnvelope.Create(canonicalMetadata, metadataTag, record.MetadataIntegrityAlgorithm);
        var json = QuarantineRecordSerializer.SerializeEnvelope(envelope);
        var finalPath = Path.Combine(_recordsDir, SafeLeaf(record.QuarantineId) + ".json");
        await WriteAtomicAsync(finalPath, System.Text.Encoding.UTF8.GetBytes(json), cancellationToken).ConfigureAwait(false);
    }

    public async Task<QuarantineStoredRecord?> ReadRecordAsync(string quarantineId, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(_recordsDir, SafeLeaf(quarantineId) + ".json");
        EnsureNoReparseAncestors(path);
        if (!File.Exists(path)) return null;
        try
        {
            var json = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            return QuarantineRecordSerializer.ToStoredRecord(json);
        }
        catch (OperationCanceledException) { throw; }
        catch (System.Exception) { return null; }
    }

    public Task<IReadOnlyList<string>> ListRecordIdsAsync(CancellationToken cancellationToken = default)
    {
        EnsureNoReparseAncestors(_recordsDir);
        if (!Directory.Exists(_recordsDir))
            return Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        var ids = Directory.EnumerateFiles(_recordsDir, "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(n => !string.IsNullOrEmpty(n))
            .Select(n => n!)
            .ToArray();
        return Task.FromResult<IReadOnlyList<string>>(ids);
    }

    public Task DeletePayloadAsync(string payloadName, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(_payloadsDir, SafeLeaf(payloadName));
        try { EnsureNoReparseAncestors(path); if (File.Exists(path)) File.Delete(path); } catch (System.Exception) { /* best-effort */ }
        return Task.CompletedTask;
    }

    private async Task WriteAtomicAsync(string finalPath, byte[] bytes, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_tempDir);
        EnsureNoReparseAncestors(finalPath);
        EnsureNoReparseAncestors(_tempDir);
        var tempPath = Path.Combine(_tempDir, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                81_920, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            EnsureNoReparseAncestors(finalPath);
            File.Move(tempPath, finalPath, overwrite: true);
        }
        catch (System.Exception)
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch (System.Exception) { /* best-effort cleanup */ }
            throw;
        }
    }

    /// <summary>
    /// Defensive: quarantine ids and payload names are service-generated GUIDs,
    /// but we still strip any path separators so a crafted name can never escape
    /// the store directory.
    /// </summary>
    private static string SafeLeaf(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Empty store key.", nameof(name));
        var leaf = Path.GetFileName(name);
        if (string.IsNullOrWhiteSpace(leaf) || leaf != name || leaf.Contains(':') || leaf.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("Store key must not contain path separators.", nameof(name));
        return leaf;
    }

    private static void EnsureNoReparseAncestors(string path)
    {
        string? current = File.Exists(path) ? Path.GetFullPath(path) : Path.GetDirectoryName(Path.GetFullPath(path));
        while (!string.IsNullOrWhiteSpace(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Quarantine store path contains a reparse point.");
            string? parent = Path.GetDirectoryName(current.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
            current = parent;
        }
    }
}
