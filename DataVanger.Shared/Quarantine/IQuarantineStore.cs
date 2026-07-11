using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Low-level storage abstraction for quarantined payloads and metadata
/// records. Implementations must commit atomically where feasible (temp file +
/// atomic move) so a crash never leaves a half-written payload or record.
///
/// Stores never decrypt, never classify, and never delete the original source
/// file — that is the service's responsibility.
/// </summary>
public interface IQuarantineStore
{
    Task WritePayloadAsync(string payloadName, QuarantineEncryptedPayload payload, CancellationToken cancellationToken = default);

    /// <summary>Returns the parsed encrypted payload, or null if it is missing.</summary>
    Task<QuarantineEncryptedPayload?> ReadPayloadAsync(string payloadName, CancellationToken cancellationToken = default);

    Task<bool> PayloadExistsAsync(string payloadName, CancellationToken cancellationToken = default);

    /// <summary>Writes the record envelope (canonical metadata + authentication tag) atomically.</summary>
    Task WriteRecordAsync(QuarantineRecord record, byte[] canonicalMetadata, byte[] metadataTag, CancellationToken cancellationToken = default);

    /// <summary>Returns the stored record (with the exact signed bytes + tag), or null if missing.</summary>
    Task<QuarantineStoredRecord?> ReadRecordAsync(string quarantineId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> ListRecordIdsAsync(CancellationToken cancellationToken = default);

    /// <summary>Removes a payload from the store (used after a successful restore-by-move). Safe no-op if absent.</summary>
    Task DeletePayloadAsync(string payloadName, CancellationToken cancellationToken = default);
}
