using DataVanger.Shared.Quarantine;

namespace DataVanger.Infrastructure.Quarantine;

/// <summary>
/// Selects the appropriate quarantine key protector for the host:
///   - Windows production: <see cref="DpapiQuarantineKeyProtector"/>.
///   - Otherwise: returns the DPAPI protector instance, whose
///     <see cref="IQuarantineKeyProtector.IsSupported"/> is false so the
///     service degrades gracefully (UnsupportedPlatform) rather than crashing.
///
/// Tests do NOT use this factory — they construct
/// InMemoryQuarantineKeyProtector directly so they never depend on DPAPI.
/// </summary>
public static class QuarantineKeyProtectorFactory
{
    public static IQuarantineKeyProtector CreateForHost(string keyDirectory)
        => new DpapiQuarantineKeyProtector(keyDirectory);
}
