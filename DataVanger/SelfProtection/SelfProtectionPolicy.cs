using System;

namespace DataVanger.SelfProtection;

/// <summary>
/// Configuration for <see cref="SelfProtectionManager"/>.
///
/// All knobs default to development-safe values so a caller that
/// constructs the manager with no arguments will:
///   - run in <see cref="SelfProtectionMode.Development"/>,
///   - never lock files,
///   - never restart processes,
///   - never spawn background threads/timers,
///   - never block dotnet build / bin+obj cleanup,
///   - emit tamper events strictly through the behavioral bus.
///
/// Production callers must opt in by setting <see cref="Mode"/> to
/// <see cref="SelfProtectionMode.Production"/> and choosing a level
/// stronger than <see cref="SelfProtectionLevel.Off"/>.
/// </summary>
public sealed class SelfProtectionPolicy
{
    /// <summary>Top-level on/off + intensity dial. Default: Basic.</summary>
    public SelfProtectionLevel Level { get; init; } = SelfProtectionLevel.Basic;

    /// <summary>Execution mode. Default: Development.</summary>
    public SelfProtectionMode Mode { get; init; } = SelfProtectionMode.Development;

    /// <summary>
    /// Upper bound on watchdog observation attempts before the watchdog
    /// stops trying. Prevents restart storms / infinite loops. Default: 3.
    /// </summary>
    public int MaxWatchdogAttempts { get; init; } = 3;

    /// <summary>
    /// Minimum delay between two watchdog attempts on the same component.
    /// The watchdog is tick-driven and never sleeps — this value is
    /// compared against the supplied "now" timestamp. Default: 30s.
    /// </summary>
    public TimeSpan WatchdogCooldown { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum number of tamper events the in-memory sink retains.
    /// Bounded to keep memory usage flat under flooding. Default: 256.
    /// </summary>
    public int TamperHistoryCapacity { get; init; } = 256;

    /// <summary>
    /// Optional diagnostic sink. Exceptions raised inside the manager are
    /// routed here instead of propagating. Default: null (silent).
    /// </summary>
    public Action<string>? Diagnostics { get; init; }

    /// <summary>
    /// A purely development-safe policy: disabled by default, no files
    /// touched, no behavioral evidence emitted. Used by tests and the
    /// initial bootstrap before the real configuration is available.
    /// </summary>
    public static SelfProtectionPolicy DevelopmentDefault() => new()
    {
        Level = SelfProtectionLevel.Basic,
        Mode = SelfProtectionMode.Development,
    };

    /// <summary>
    /// A safe production starting point: Standard level, Production mode,
    /// conservative cooldowns. Callers can override individual fields with
    /// a record-style `with` expression.
    /// </summary>
    public static SelfProtectionPolicy ProductionStandard() => new()
    {
        Level = SelfProtectionLevel.Standard,
        Mode = SelfProtectionMode.Production,
        MaxWatchdogAttempts = 3,
        WatchdogCooldown = TimeSpan.FromSeconds(30),
    };
}
