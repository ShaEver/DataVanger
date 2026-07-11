namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Protects the local quarantine key material at rest and yields the working
/// keys for payload encryption and metadata authentication.
///
/// Platform behavior:
///   - Production Windows: DPAPI (ProtectedData) protector.
///   - Development/Test: deterministic in-memory protector.
///   - Unsupported platform: <see cref="IsSupported"/> is false and the
///     service degrades gracefully with UnsupportedPlatform — it never calls
///     <see cref="GetKeyMaterial"/> on an unsupported protector and never
///     crashes.
///
/// Implementations MUST NOT log key material or write unprotected keys to disk.
/// </summary>
public interface IQuarantineKeyProtector
{
    QuarantineKeyProtectionMode Mode { get; }

    bool IsSupported { get; }

    /// <summary>
    /// Returns the (in-memory) working key material. Only called by the service
    /// after confirming <see cref="IsSupported"/> is true.
    /// </summary>
    QuarantineKeyMaterial GetKeyMaterial();
}
