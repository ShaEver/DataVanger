using System.Collections.Generic;
using DataVanger.Core;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Encapsulates the encrypted on-disk quarantine store. Implementations must
/// never delete the original file before the encrypted copy is written and
/// flushed.
/// </summary>
public interface IQuarantineService
{
    /// <summary>
    /// Moves the file referenced by <paramref name="finding"/> into quarantine.
    /// Returns the new quarantine ID on success, or <c>null</c> on failure.
    /// </summary>
    string? Quarantine(ScanFinding finding);

    /// <summary>Restores a previously quarantined file by ID. Returns true on success.</summary>
    bool Restore(string id);

    /// <summary>Returns a snapshot of the quarantine index.</summary>
    IReadOnlyDictionary<string, QuarantineEntry> List();
}
