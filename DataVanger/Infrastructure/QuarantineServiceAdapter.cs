using System.Collections.Generic;
using DataVanger.Core;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// Adapter exposing <see cref="QuarantineManager"/> as <see cref="IQuarantineService"/>.
/// Lets future call sites depend on the abstraction instead of the concrete
/// manager. <see cref="QuarantineManager"/> stays as the on-disk implementation.
/// </summary>
public sealed class QuarantineServiceAdapter : IQuarantineService
{
    private readonly QuarantineManager _inner;

    public QuarantineServiceAdapter(QuarantineManager inner) { _inner = inner; }

    public string? Quarantine(ScanFinding finding) => _inner.Quarantine(finding);

    public bool Restore(string id) => _inner.Restore(id);

    public IReadOnlyDictionary<string, QuarantineEntry> List() => _inner.List();
}
