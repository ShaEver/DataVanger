using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace DataVanger.Core;

public class AppSettings
{
    // ---- Schema versioning (phase 10) -------------------------------------------
    // CurrentSchemaVersion is bumped when the settings schema changes; add the matching
    // case to Migrate(...). New instances are always stamped with the current version.
    public const int CurrentSchemaVersion = 1;
    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public List<string> ExtraTargets { get; set; } = new();
    public List<string> ExcludedPaths { get; set; } = new();
    // Base trusted-publisher policy (single source of truth). Centralised here so
    // ScanEngine and ReputationEngine no longer carry their own hardcoded copies.
    // BETA 11D: production matching is ANCHORED to RDN component starts (a trusted name
    // must begin a component value at a boundary), so short forms (e.g. "NVIDIA") still
    // cover their longer certificate subjects without being spoofable by a name appearing
    // elsewhere in the subject; trust additionally requires a VALID signature. Deliberately
    // excludes OpenAI / Wondershare / SweetLabs: if a user trusts those, they add them via
    // ExtraTrustedPublishers below rather than shipping them as defaults.
    public List<string> TrustedPublishers { get; set; } = DefaultTrustedPublishers();

    // User-editable additive list, merged on top of TrustedPublishers.
    public List<string> ExtraTrustedPublishers { get; set; } = new();

    // Phase 11 — opt-in publisher identity assurance. Default Substring preserves the legacy
    // case-insensitive trusted-name match exactly (no behaviour change). Stronger modes
    // (ChainAndName / ChainAndThumbprint) require certificate evidence and are validated by
    // PublisherIdentity; on the current name-only signer path they fail closed. Enabling a
    // stronger default is approval-gated and needs Windows corpus validation.
    public PublisherValidationMode PublisherValidationMode { get; set; } = PublisherValidationMode.Substring;

    // Optional certificate thumbprints to pin under ChainAndThumbprint. Empty/malformed entries
    // never grant trust. Not used by the default Substring mode.
    public List<string> TrustedPublisherThumbprints { get; set; } = new();

    public int MinScoreToReport { get; set; } = RiskThresholds.Suspect;
    public int MinScoreToQuarantine { get; set; } = RiskThresholds.High;
    public bool AutoQuarantineKnownMalware { get; set; } = true;
    public bool SuppressAccessDeniedLog { get; set; } = true;
    public bool ScanStartupLocations { get; set; } = true;
    public bool ScanDownloads { get; set; } = true;
    public bool ScanDesktop { get; set; } = true;
    public bool ScanDocuments { get; set; } = true;
    public bool ScanAppData { get; set; } = true;
    public bool EnableTrayProtection { get; set; } = false;
    public bool EnableYaraRules { get; set; } = true;
    public bool DeepScanArchives { get; set; } = true;
    public int YaraMaxScanSizeMB { get; set; } = 32;

    // Phase 13 — bounded local YARA rule-pack loading. Generous defaults that bound pathological
    // packs without limiting real-world ones. Any ≤0 (invalid) value is clamped to the default at
    // load time by RulePackLimits.From, so old/missing config remains safe.
    public int YaraMaxRuleFiles { get; set; } = 5000;
    public int YaraMaxRuleFileSizeKB { get; set; } = 2048;
    public int YaraMaxRulePackSizeMB { get; set; } = 128;

    // Phase 14 — opt-in HTTP transport for signed updates. DISABLED by default; an empty feed
    // URL means no network I/O. These are operator-facing knobs only: mapping into the bounded
    // HttpUpdateTransport (HttpUpdateTransportOptions.Create) and wiring it into the update
    // service live in a future composition layer, because DataVanger.Engine does not reference
    // this UI-layer settings type. Any ≤0 numeric value normalizes to a safe default when
    // mapped, so old/missing config stays safe and bounded.
    public bool EnableHttpSignedUpdates { get; set; } = false;
    public string SignedUpdateFeedUrl { get; set; } = "";
    public int SignedUpdateHttpTimeoutSeconds { get; set; } = 30;
    public int SignedUpdateMaxManifestSizeKB { get; set; } = 512;
    public int SignedUpdateMaxPackageSizeMB { get; set; } = 128;

    // F1 composition — the pinned public key + identity used to verify the signed feed's
    // manifest. A blank key/keyId keeps signed updates inert even when EnableHttpSignedUpdates
    // is true (the runner then falls back to the legacy unsigned URL fetch). Additive optional
    // fields: an absent value deserialises to these defaults, so no schema bump is required.
    public string SignedUpdatePublicKeyPem { get; set; } = "";
    public string SignedUpdateKeyId { get; set; } = "";
    public string SignedUpdateAlgorithm { get; set; } = "RSA-PSS-SHA256";
    public string SignedUpdateFeedId { get; set; } = "datavanger-default-feed";

    public int ArchiveMaxEntries { get; set; } = 600;
    public int ArchiveMaxDepth { get; set; } = 2;
    public int ArchiveMaxDecompressedMB { get; set; } = 512;
    public bool IncludeRemovableDrives { get; set; } = false;
    public bool AnalyzeDocuments { get; set; } = true;
    public bool AnalyzeBrowserExtensions { get; set; } = true;
    public bool AnalyzeAlternateDataStreams { get; set; } = true;
    public bool AdvancedPersistenceChecks { get; set; } = true;
    public bool AnalyzeServicesAndDrivers { get; set; } = true;
    public bool AnalyzeScheduledTasks { get; set; } = true;
    public bool UseSafeCache { get; set; } = true;
    public string SignatureUpdateUrl { get; set; } = "";

    // Phase 11 — opt-in detailed telemetry export. When enabled, generates
    // DataVanger_Telemetry.json with per-stage breakdown, percentiles, and
    // slow-path analysis. Used for performance profiling and regression detection
    // before/after optimization phases. Default off to avoid output spam.
    public bool EnableDetailedTelemetry { get; set; } = false;

    // Curated base trusted-publisher policy (phase 06) — single source of truth, used
    // both as the property default and to normalise an explicit-null value on load.
    // Deliberately excludes OpenAI / Wondershare / SweetLabs (users add their own via
    // ExtraTrustedPublishers). Returns a fresh list so instances never share state.
    internal static List<string> DefaultTrustedPublishers() => new()
    {
        "Microsoft",
        "Intel",
        "NVIDIA",
        "NVIDIA Corporation",
        "AMD",
        "Advanced Micro Devices",
        "Google",
        "Google LLC",
        "Mozilla",
        "Mozilla Corporation",
        "Spotify",
        "Valve",
        "Valve Corporation",
        "Adobe",
        "Adobe Inc",
        "Oracle",
        "Oracle Corporation",
        // BETA 11D — additional well-known signers (anchored matching makes these safe).
        "Anthropic",
        "Apple",
        "Realtek",
        "Realtek Semiconductor",
        "Lenovo",
        "Dell",
        "Hewlett-Packard",
        "HP Inc",
        "ASUSTeK",
        "Logitech",
        "Qualcomm",
        "Citrix Systems",
    };

    public static AppSettings Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                var created = new AppSettings();
                created.Save(path);
                return created;
            }

            var raw = File.ReadAllText(path);
            var loaded = JsonSerializer.Deserialize<AppSettings>(raw);
            if (loaded is null) return new AppSettings();

            return Migrate(loaded, loaded.SchemaVersion);
        }
        catch (System.Exception)
        {
            return new AppSettings();
        }
    }

    // Deterministic, lossless forward migration. Only fills genuinely absent/unsafe
    // values and never overwrites a user-set value:
    //   - Absent list properties keep their initializer defaults (curated
    //     TrustedPublishers / empty lists) because System.Text.Json leaves unset
    //     properties untouched.
    //   - An explicit empty list is preserved (the user intentionally cleared it).
    //   - An explicit JSON null is normalised to a safe non-null value to avoid
    //     downstream NREs (TrustedPublishers -> curated defaults; others -> empty).
    //
    // Note: SchemaVersion is initialised to CurrentSchemaVersion, so a config that omits
    // the field deserialises with the current version rather than 0. The v0/v1 migration
    // is identical (normalise + stamp version), so the outcome is correct either way. A
    // future version that must distinguish "absent" from an explicit value should detect
    // field presence from the raw JSON (e.g. JsonDocument) at that point.
    private static AppSettings Migrate(AppSettings loaded, int fromVersion)
    {
        loaded.ExtraTargets ??= new List<string>();
        loaded.ExcludedPaths ??= new List<string>();
        loaded.TrustedPublishers ??= DefaultTrustedPublishers();
        loaded.ExtraTrustedPublishers ??= new List<string>();
        loaded.TrustedPublisherThumbprints ??= new List<string>(); // phase 11: explicit null -> empty

        // v0 (pre-versioning baseline) and v1 require only the normalisation above.
        // PublisherValidationMode is an additive optional field; an absent value deserialises to
        // the Substring default, so no schema-version bump is required for backward compatibility.
        _ = fromVersion;
        loaded.SchemaVersion = CurrentSchemaVersion;
        return loaded;
    }

    public void Save(string path)
    {
        SchemaVersion = CurrentSchemaVersion;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(this, opts));
    }
}
