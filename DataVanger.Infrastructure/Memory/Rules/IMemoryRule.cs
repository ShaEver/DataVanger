using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// One memory inspection rule. Rules look at a single region (with
/// optionally-read bytes) and return zero or more findings. They must
/// be cheap, side-effect free, and never throw.
/// </summary>
public interface IMemoryRule
{
    string RuleId { get; }
    string Title { get; }

    /// <summary>True if the rule wants bytes from the region.</summary>
    bool RequiresBytes { get; }

    IReadOnlyList<MemoryFinding> Evaluate(
        ProcessSnapshot process,
        MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken);
}
