namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// The kind of normalized file-activity observation produced by the
/// <c>ProtectedFilesActivityEventAdapter</c> from a
/// <see cref="DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent"/>.
///
/// Observations are descriptive, normalized inputs to the conservative
/// scoring policy. They are NOT verdicts.
/// </summary>
public enum ProtectedFileObservationKind
{
    Unknown = 0,

    /// <summary>A file was created.</summary>
    FileCreated,

    /// <summary>A file was modified / written.</summary>
    FileModified,

    /// <summary>A file was renamed (possibly with an extension transition).</summary>
    FileRenamed,

    /// <summary>A file was deleted.</summary>
    FileDeleted,

    /// <summary>
    /// A recovery-protection indicator was observed, represented purely as
    /// one or more normalized metadata labels (e.g.
    /// <c>shadow-copy-removal-indicator</c>). The monitor NEVER parses,
    /// reconstructs, emits, or executes the underlying OS commands — it
    /// only records the pre-normalized label.
    /// </summary>
    RecoveryIndicator,
}
