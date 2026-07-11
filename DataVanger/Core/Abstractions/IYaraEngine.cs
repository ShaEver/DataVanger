using System.Collections.Generic;
using DataVanger.Core;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Pluggable YARA-style scanner. The current implementation is the built-in
/// <c>LightweightYaraDatabase</c>; a future real-YARA backend can replace it
/// without touching the detection modules.
/// </summary>
public interface IYaraEngine
{
    /// <summary>Number of rules currently loaded.</summary>
    int RuleCount { get; }

    /// <summary>Scans a single file and returns all matches.</summary>
    IReadOnlyList<LightweightYaraMatch> Scan(string filePath, int maxScanSizeMB);
}
