using System.Collections.Generic;
using DataVanger.Core;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// Adapter exposing <see cref="LightweightYaraDatabase"/> through
/// <see cref="IYaraEngine"/>.
/// </summary>
public sealed class YaraEngineAdapter : IYaraEngine
{
    private readonly LightweightYaraDatabase _db;

    public YaraEngineAdapter(LightweightYaraDatabase db) { _db = db; }

    public int RuleCount => _db.Count;

    public IReadOnlyList<LightweightYaraMatch> Scan(string filePath, int maxScanSizeMB) =>
        _db.ScanFile(filePath, maxScanSizeMB);
}
