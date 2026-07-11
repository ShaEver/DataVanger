using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Core.Abstractions;

namespace DataVanger.Engine;

/// <summary>
/// Ordered collection of detection modules executed for each file.
///
/// Order matters:
///   1. Hash module first — sets KnownMalicious early so later modules can
///      cheaply short-circuit.
///   2. Heuristic module — emits scoreable evidence used to gate expensive
///      modules (YARA, signature check) downstream.
///   3. Content-specific modules (script, PE, archive, document, browser).
///   4. YARA last — most expensive, runs only when content fits the budget.
///   5. Persistence — applied after content analysis so its score boost
///      uses the latest context.
///
/// The registry is immutable once built; future runtime DI can swap it via
/// configuration.
/// </summary>
public sealed class DetectionModuleRegistry
{
    private readonly IDetectionModule[] _modules;

    public DetectionModuleRegistry(IEnumerable<IDetectionModule> modules)
    {
        _modules = (modules ?? throw new ArgumentNullException(nameof(modules))).ToArray();
    }

    public IReadOnlyList<IDetectionModule> Modules => _modules;

    public IDetectionModule? Find(string name) =>
        _modules.FirstOrDefault(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase));
}
