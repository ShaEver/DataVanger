using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Versioned listing of quarantine records. The index is a convenience view —
/// it is never blindly trusted: each record remains independently verifiable
/// through <see cref="IQuarantineService.VerifyAsync"/>.
/// </summary>
public interface IQuarantineIndex
{
    Task<IReadOnlyList<QuarantineIndexEntry>> ListAsync(CancellationToken cancellationToken = default);
}
