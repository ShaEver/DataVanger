using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Remediation.Files;

/// <summary>
/// The remediation layer's view of Secure Quarantine V2. It exposes exactly the
/// operations file remediation needs and NOTHING that could change quarantine
/// semantics: store, verify, restore, and read a record. Restore is delegated
/// unchanged so the existing strong restore warnings and integrity checks are
/// preserved.
/// </summary>
public interface IQuarantineRemediationGateway
{
    Task<QuarantineResult> QuarantineAsync(QuarantineRequest request, CancellationToken cancellationToken = default);
    Task<QuarantineIntegrityResult> VerifyAsync(string quarantineId, CancellationToken cancellationToken = default);
    Task<QuarantineRestoreResult> RestoreAsync(QuarantineRestoreRequest request, CancellationToken cancellationToken = default);
    Task<QuarantineRecord?> GetAsync(string quarantineId, CancellationToken cancellationToken = default);
}

/// <summary>Thin adapter over the real <see cref="IQuarantineService"/>. Adds no
/// logic: it only narrows the surface to what remediation may use.</summary>
public sealed class QuarantineServiceRemediationGateway : IQuarantineRemediationGateway
{
    private readonly IQuarantineService _service;

    public QuarantineServiceRemediationGateway(IQuarantineService service)
        => _service = service ?? throw new System.ArgumentNullException(nameof(service));

    public Task<QuarantineResult> QuarantineAsync(QuarantineRequest request, CancellationToken cancellationToken = default)
        => _service.QuarantineAsync(request, cancellationToken);

    public Task<QuarantineIntegrityResult> VerifyAsync(string quarantineId, CancellationToken cancellationToken = default)
        => _service.VerifyAsync(quarantineId, cancellationToken);

    public Task<QuarantineRestoreResult> RestoreAsync(QuarantineRestoreRequest request, CancellationToken cancellationToken = default)
        => _service.RestoreAsync(request, cancellationToken);

    public Task<QuarantineRecord?> GetAsync(string quarantineId, CancellationToken cancellationToken = default)
        => _service.GetAsync(quarantineId, cancellationToken);
}

/// <summary>
/// Removes a quarantine STORE record's encrypted payload — retention cleanup,
/// NOT original-file deletion. Keyed only by quarantine id; it can never receive
/// a filesystem path, so it cannot delete an arbitrary original file.
/// </summary>
public interface IQuarantineStoreCleanup
{
    /// <summary>Removes the encrypted payload for the given quarantine record.
    /// Returns true if a payload was present and removed.</summary>
    Task<bool> RemovePayloadAsync(string payloadName, CancellationToken cancellationToken = default);
}

/// <summary>Default store cleanup over the low-level <see cref="IQuarantineStore"/>
/// (uses the existing payload-delete primitive — safe no-op if absent).</summary>
public sealed class QuarantineStoreCleanup : IQuarantineStoreCleanup
{
    private readonly IQuarantineStore _store;

    public QuarantineStoreCleanup(IQuarantineStore store)
        => _store = store ?? throw new System.ArgumentNullException(nameof(store));

    public async Task<bool> RemovePayloadAsync(string payloadName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(payloadName)) return false;
        bool existed = await _store.PayloadExistsAsync(payloadName, cancellationToken).ConfigureAwait(false);
        await _store.DeletePayloadAsync(payloadName, cancellationToken).ConfigureAwait(false);
        return existed;
    }
}
