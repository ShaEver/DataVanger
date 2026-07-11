using System;
using System.Collections.Generic;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Normalized recovery-protection indicator labels for the Protected
/// Files Activity Monitor (Phase 2 / Step 07).
///
/// EXTREMELY IMPORTANT SAFETY CONTRACT:
///   These are METADATA LABELS ONLY. This type does NOT generate,
///   reconstruct, parse, emit, document, or execute any operating-system
///   command associated with these indicators (no vssadmin, no wbadmin,
///   no bcdedit, no wmic shadowcopy, no cipher, etc.). It only reads
///   pre-normalized labels that an upstream producer already placed on a
///   runtime event's metadata. Tests simulate labels only.
///
///   The presence of a label is EVIDENCE ONLY and is never, by itself,
///   ConfirmedMalware.
/// </summary>
public static class RecoveryProtectionIndicators
{
    /// <summary>A shadow-copy removal indicator (label only — no command).</summary>
    public const string ShadowCopyRemovalIndicator = "shadow-copy-removal-indicator";

    /// <summary>A backup-catalog removal indicator (label only — no command).</summary>
    public const string BackupCatalogRemovalIndicator = "backup-catalog-removal-indicator";

    /// <summary>A recovery-configuration tamper indicator (label only — no command).</summary>
    public const string RecoveryConfigurationTamperIndicator = "recovery-configuration-tamper-indicator";

    /// <summary>A free-space overwrite indicator (label only — no command).</summary>
    public const string FreeSpaceOverwriteIndicator = "free-space-overwrite-indicator";

    /// <summary>
    /// Metadata key prefix under which producers place normalized
    /// indicator labels. A key of the form
    /// <c>protectedfiles.recovery_indicator</c> (single label) or
    /// <c>protectedfiles.recovery.&lt;name&gt;</c> (flag) is recognized.
    /// </summary>
    public const string MetaSingle = "protectedfiles.recovery_indicator";
    public const string MetaPrefix = "protectedfiles.recovery.";

    private static readonly HashSet<string> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        ShadowCopyRemovalIndicator,
        BackupCatalogRemovalIndicator,
        RecoveryConfigurationTamperIndicator,
        FreeSpaceOverwriteIndicator,
    };

    /// <summary>True when the supplied label is a recognized normalized indicator.</summary>
    public static bool IsKnown(string? label)
        => !string.IsNullOrWhiteSpace(label) && Known.Contains(Normalize(label!));

    /// <summary>
    /// Extracts recognized normalized indicator labels from event
    /// metadata. Reads labels ONLY; never parses commands. Never throws.
    /// </summary>
    public static IReadOnlyList<string> Extract(IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata is null || metadata.Count == 0) return Array.Empty<string>();

        List<string>? result = null;
        foreach (var kvp in metadata)
        {
            string? label = null;

            if (kvp.Key.Equals(MetaSingle, StringComparison.OrdinalIgnoreCase))
            {
                label = kvp.Value;
            }
            else if (kvp.Key.StartsWith(MetaPrefix, StringComparison.OrdinalIgnoreCase))
            {
                // Flag form: protectedfiles.recovery.<name> = true|1.
                if (IsTruthy(kvp.Value))
                {
                    label = MapSuffix(kvp.Key.Substring(MetaPrefix.Length));
                }
            }

            if (IsKnown(label))
            {
                var normalized = Normalize(label!);
                (result ??= new List<string>()).Add(normalized);
            }
        }

        if (result is null) return Array.Empty<string>();

        // De-duplicate while preserving order.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var distinct = new List<string>(result.Count);
        foreach (var label in result)
        {
            if (seen.Add(label)) distinct.Add(label);
        }
        return distinct;
    }

    private static string MapSuffix(string suffix) => suffix.ToLowerInvariant() switch
    {
        "shadow_copy_removal" or "shadowcopyremoval" => ShadowCopyRemovalIndicator,
        "backup_catalog_removal" or "backupcatalogremoval" => BackupCatalogRemovalIndicator,
        "recovery_configuration_tamper" or "recoveryconfigurationtamper" => RecoveryConfigurationTamperIndicator,
        "free_space_overwrite" or "freespaceoverwrite" => FreeSpaceOverwriteIndicator,
        _ => suffix,
    };

    private static bool IsTruthy(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return value.Trim() is "1" or "true" or "True" or "TRUE" or "yes" or "Yes";
    }

    private static string Normalize(string label) => label.Trim().ToLowerInvariant();
}
