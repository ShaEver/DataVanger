namespace DataVanger.SelfProtection;

/// <summary>
/// Execution mode for the Self-Protection subsystem.
///
/// <see cref="Development"/> is the safe default for tests, dotnet build
/// and Visual Studio: no filesystem locks are taken, no watchdog process
/// restart is attempted, and tamper signals are recorded but never
/// promoted past behavioral evidence. This guarantees the dev loop
/// (clean bin/obj, edit, rebuild) is never blocked by self-protection.
///
/// <see cref="Production"/> enables the (still defensive) integrity and
/// watchdog observation behavior. Even in production mode the subsystem
/// never blocks legitimate administration, never injects, never hooks
/// the kernel and never produces ConfirmedMalware verdicts.
/// </summary>
public enum SelfProtectionMode
{
    Development = 0,
    Production = 1,
}
