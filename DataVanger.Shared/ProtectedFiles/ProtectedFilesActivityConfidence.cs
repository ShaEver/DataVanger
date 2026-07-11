namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Confidence the monitor has in a protected-file activity evidence item.
///
/// Confidence is descriptive only and has NO classification authority.
/// Even <see cref="High"/> confidence activity evidence can never, by
/// itself, become ConfirmedMalware.
/// </summary>
public enum ProtectedFilesActivityConfidence
{
    Low = 0,
    Medium,
    High,
}
