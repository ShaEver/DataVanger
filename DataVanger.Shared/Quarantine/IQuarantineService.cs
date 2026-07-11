using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// High-level Secure Quarantine V2 API used by the scan/response pipeline,
/// service runtime, UI, reporting, and tests.
///
/// All operations are non-throwing for normal operational failures: they
/// return structured results. None of them ever produces a malware verdict;
/// automatic quarantine is honored only for ConfirmedMalware requests.
/// </summary>
public interface IQuarantineService
{
    Task<QuarantineResult> QuarantineAsync(QuarantineRequest request, CancellationToken cancellationToken = default);

    Task<QuarantineRestoreResult> RestoreAsync(QuarantineRestoreRequest request, CancellationToken cancellationToken = default);

    Task<QuarantineIntegrityResult> VerifyAsync(string quarantineId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<QuarantineIndexEntry>> ListAsync(CancellationToken cancellationToken = default);

    Task<QuarantineRecord?> GetAsync(string quarantineId, CancellationToken cancellationToken = default);
}
