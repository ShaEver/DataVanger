using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Quarantine;

/// <summary>
/// Deterministic in-memory quarantine store for tests and non-persistent
/// scenarios. Payloads are kept as the encoded ".qbin" bytes (exactly what the
/// filesystem store would write) so the same encode/decode and tamper paths are
/// exercised. Writes are effectively atomic (single dictionary assignment under
/// a lock); there is no partial-write window.
/// </summary>
public sealed class InMemoryQuarantineStore : IQuarantineStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, byte[]> _payloads = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _records = new(StringComparer.Ordinal);

    public Task WritePayloadAsync(string payloadName, QuarantineEncryptedPayload payload, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var encoded = QuarantinePayloadCodec.Encode(payload);
        lock (_gate) _payloads[payloadName] = encoded;
        return Task.CompletedTask;
    }

    public Task<QuarantineEncryptedPayload?> ReadPayloadAsync(string payloadName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[]? raw;
        lock (_gate) _payloads.TryGetValue(payloadName, out raw);
        if (raw is null) return Task.FromResult<QuarantineEncryptedPayload?>(null);
        return Task.FromResult(QuarantinePayloadCodec.TryDecode(raw, "AES-256-GCM"));
    }

    public Task<bool> PayloadExistsAsync(string payloadName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate) return Task.FromResult(_payloads.ContainsKey(payloadName));
    }

    public Task WriteRecordAsync(QuarantineRecord record, byte[] canonicalMetadata, byte[] metadataTag, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var envelope = QuarantineRecordEnvelope.Create(canonicalMetadata, metadataTag, record.MetadataIntegrityAlgorithm);
        var json = QuarantineRecordSerializer.SerializeEnvelope(envelope);
        lock (_gate) _records[record.QuarantineId] = json;
        return Task.CompletedTask;
    }

    public Task<QuarantineStoredRecord?> ReadRecordAsync(string quarantineId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string? json;
        lock (_gate) _records.TryGetValue(quarantineId, out json);
        if (json is null) return Task.FromResult<QuarantineStoredRecord?>(null);
        return Task.FromResult(QuarantineRecordSerializer.ToStoredRecord(json));
    }

    public Task<IReadOnlyList<string>> ListRecordIdsAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate) return Task.FromResult<IReadOnlyList<string>>(_records.Keys.ToArray());
    }

    public Task DeletePayloadAsync(string payloadName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate) _payloads.Remove(payloadName);
        return Task.CompletedTask;
    }

    // ── Test-support tamper helpers (deterministic; never used in production) ──
    /// <summary>Overwrites a stored payload's raw bytes to simulate tampering.</summary>
    public void TamperPayloadRaw(string payloadName, Func<byte[], byte[]> mutate)
    {
        lock (_gate)
        {
            if (_payloads.TryGetValue(payloadName, out var raw))
                _payloads[payloadName] = mutate(raw);
        }
    }

    /// <summary>Overwrites a stored record envelope JSON to simulate metadata tampering.</summary>
    public void TamperRecordJson(string quarantineId, Func<string, string> mutate)
    {
        lock (_gate)
        {
            if (_records.TryGetValue(quarantineId, out var json))
                _records[quarantineId] = mutate(json);
        }
    }

    public void RemovePayload(string payloadName)
    {
        lock (_gate) _payloads.Remove(payloadName);
    }
}
