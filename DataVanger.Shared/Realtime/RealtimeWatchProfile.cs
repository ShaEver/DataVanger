using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Configurable real-time watch profile. Profiles describe which
/// directories the orchestrator should observe and how to filter the
/// raw event stream.
///
/// Development-safe defaults:
///   - DevelopmentSafe profiles never expand to the repository root.
///   - bin/, obj/, .git/, .vs/, TestResults/, coverage/ are always
///     suggested as exclusions when DevelopmentSafe=true.
///   - The model is purely data; orchestration policy is owned by the
///     service.
/// </summary>
public sealed class RealtimeWatchProfile
{
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// Directory to observe. May be missing/unavailable at runtime —
    /// the orchestrator degrades gracefully instead of crashing.
    /// </summary>
    public string Path { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    public bool IncludeSubdirectories { get; init; } = false;

    /// <summary>
    /// When true, the orchestrator applies the conservative
    /// development-mode exclusion list (bin/obj/.git/.vs/TestResults/
    /// coverage/*.user/*.suo/*.tmp) on top of any per-profile rules.
    /// </summary>
    public bool DevelopmentSafe { get; init; } = true;

    /// <summary>
    /// Optional list of file extensions (lowercase, with leading dot)
    /// that are eligible for scanning when produced by this profile.
    /// Empty list means "use the global eligibility filter".
    /// </summary>
    public IReadOnlyList<string> IncludeExtensions { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Optional list of file extensions (lowercase, with leading dot)
    /// that should be ignored even if they would otherwise be eligible.
    /// </summary>
    public IReadOnlyList<string> ExcludeExtensions { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Substring fragments that, if present in a normalized full path,
    /// cause the event to be skipped. Matched case-insensitively.
    /// </summary>
    public IReadOnlyList<string> ExcludePathFragments { get; init; } = Array.Empty<string>();
}
