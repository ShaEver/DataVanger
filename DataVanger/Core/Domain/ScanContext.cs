using System.Collections.Generic;
using DataVanger.Core;
using DataVanger.Core.Abstractions;

namespace DataVanger.Core.Domain;

/// <summary>
/// Read-only state shared across one whole scan run.
///
/// The pipeline builds a single <see cref="ScanContext"/> at the start of a
/// scan and passes it to every detection module. It is intentionally a value
/// container with no behavior — services live behind the <c>Abstractions</c>
/// interfaces so modules can be tested in isolation.
/// </summary>
public sealed class ScanContext
{
    public ScanContext(
        ScanOptions options,
        AppSettings settings,
        IReadOnlyCollection<string> runningProcessPaths,
        IReadOnlyCollection<string> persistenceExactPaths,
        string persistenceBlob)
    {
        Options = options;
        Settings = settings;
        RunningProcessPaths = runningProcessPaths;
        PersistenceExactPaths = persistenceExactPaths;
        PersistenceBlob = persistenceBlob;
    }

    public ScanOptions Options { get; }
    public AppSettings Settings { get; }
    public ScanProfile Profile => Options.Profile;
    public bool Deep => Profile == ScanProfile.Deep;

    /// <summary>Lower-cased absolute paths of all running processes.</summary>
    public IReadOnlyCollection<string> RunningProcessPaths { get; }

    /// <summary>Lower-cased paths extracted from persistence entry strings.</summary>
    public IReadOnlyCollection<string> PersistenceExactPaths { get; }

    /// <summary>Concatenated persistence text blob for substring matching.</summary>
    public string PersistenceBlob { get; }
}
