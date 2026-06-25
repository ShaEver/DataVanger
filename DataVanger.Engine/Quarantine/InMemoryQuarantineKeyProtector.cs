using System;
using System.Security.Cryptography;
using System.Text;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Quarantine;

/// <summary>
/// Deterministic in-memory key protector for tests and non-persistent
/// scenarios (Secure Quarantine V2).
///
/// It holds a master key in process memory only — nothing is written to disk
/// and DPAPI is never required. Two independent subkeys (payload + metadata)
/// are derived from the master key using HKDF-SHA256 with distinct labels.
///
/// A fixed <c>seed</c> yields the same keys every run, which makes crypto
/// round-trip tests fully deterministic. With no seed, a cryptographically
/// random master key is generated.
///
/// Key material never leaves this object except as the derived
/// <see cref="QuarantineKeyMaterial"/> handed to the crypto provider, and is
/// never logged.
/// </summary>
public sealed class InMemoryQuarantineKeyProtector : IQuarantineKeyProtector
{
    private readonly byte[] _payloadKey;
    private readonly byte[] _metadataKey;

    public InMemoryQuarantineKeyProtector(string? seed = null)
    {
        byte[] master = seed is null
            ? RandomNumberGenerator.GetBytes(32)
            : SHA256.HashData(Encoding.UTF8.GetBytes("DataVanger.Quarantine.V2.InMemory|" + seed));

        var material = QuarantineKeyDerivation.FromMaster(master);
        _payloadKey = material.PayloadKey;
        _metadataKey = material.MetadataKey;
    }

    public QuarantineKeyProtectionMode Mode => QuarantineKeyProtectionMode.InMemory;

    public bool IsSupported => true;

    public QuarantineKeyMaterial GetKeyMaterial() => new(_payloadKey, _metadataKey);
}
