using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Top-level scan entry point. Implementations orchestrate target discovery,
/// per-file detection module execution, classification, quarantine and
/// reporting. The UI talks to this interface only.
/// </summary>
public interface IScanEngine
{
    Task<(List<ScanFinding> findings, ScanMetrics metrics)> RunAsync(
        ScanOptions options,
        Action<string> log,
        CancellationToken cancellationToken,
        Action<int, int>? onProgress = null,
        Action<ScanProgressInfo>? onProgressInfo = null);
}
