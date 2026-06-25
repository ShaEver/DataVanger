using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Infrastructure.Quarantine;

/// <summary>
/// Windows-only quarantine key protector backed by DPAPI
/// (<see cref="ProtectedData"/>), introduced for Secure Quarantine V2.
///
/// Design / safety:
///   - DPAPI is Windows-only. Every ProtectedData call is guarded by
///     <see cref="OperatingSystem.IsWindows()"/>. On any non-Windows host
///     <see cref="IsSupported"/> is false and the quarantine service degrades
///     gracefully (UnsupportedPlatform) — <see cref="GetKeyMaterial"/> is never
///     invoked by the service when unsupported.
///   - A random 256-bit master key is generated once, DPAPI-protected, and
///     persisted as an opaque blob. Subkeys are derived via HKDF. The master
///     key is never written unprotected and never logged.
///   - This implementation lives in DataVanger.Infrastructure (not Shared) so
///     the DPAPI dependency stays isolated, per the phase requirements.
/// </summary>
public sealed class DpapiQuarantineKeyProtector : IQuarantineKeyProtector
{
    private readonly string _keyBlobPath;
    private readonly byte[] _entropy;
    private readonly object _gate = new();
    private QuarantineKeyMaterial? _cached;

    public DpapiQuarantineKeyProtector(string keyDirectory, byte[]? optionalEntropy = null)
    {
        if (string.IsNullOrWhiteSpace(keyDirectory)) throw new ArgumentException("Key directory is required.", nameof(keyDirectory));
        _keyBlobPath = Path.Combine(Path.GetFullPath(keyDirectory), "quarantine.v2.key");
        _entropy = optionalEntropy ?? System.Text.Encoding.UTF8.GetBytes("DataVanger.Quarantine.V2.DPAPI");
    }

    public QuarantineKeyProtectionMode Mode =>
        OperatingSystem.IsWindows() ? QuarantineKeyProtectionMode.DpapiWindows : QuarantineKeyProtectionMode.UnsupportedPlatform;

    public bool IsSupported => OperatingSystem.IsWindows();

    public QuarantineKeyMaterial GetKeyMaterial()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("DPAPI quarantine key protection is only available on Windows.");

        lock (_gate)
        {
            _cached ??= QuarantineKeyDerivation.FromMaster(LoadOrCreateMasterWindows());
            return _cached;
        }
    }

    [SupportedOSPlatform("windows")]
    private byte[] LoadOrCreateMasterWindows()
    {
        var dir = Path.GetDirectoryName(_keyBlobPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        if (File.Exists(_keyBlobPath))
        {
            var protectedBlob = File.ReadAllBytes(_keyBlobPath);
            return ProtectedData.Unprotect(protectedBlob, _entropy, DataProtectionScope.CurrentUser);
        }

        var master = RandomNumberGenerator.GetBytes(32);
        var blob = ProtectedData.Protect(master, _entropy, DataProtectionScope.CurrentUser);

        // Stage to temp + atomic move so a crash never leaves a partial key blob.
        var tempPath = _keyBlobPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllBytes(tempPath, blob);
        File.Move(tempPath, _keyBlobPath, overwrite: true);
        return master;
    }
}
