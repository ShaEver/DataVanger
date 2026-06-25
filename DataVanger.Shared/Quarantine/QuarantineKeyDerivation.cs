using System.Security.Cryptography;
using System.Text;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Deterministic subkey derivation for quarantine. Two independent 256-bit keys
/// (payload encryption + metadata authentication) are derived from a single
/// protected master key using HKDF-SHA256 with distinct info labels.
///
/// Centralized so the in-memory (test) protector and the DPAPI (production)
/// protector derive identical subkeys from the same master, and so the
/// derivation is never duplicated/diverged.
/// </summary>
public static class QuarantineKeyDerivation
{
    private static readonly byte[] Salt = Encoding.UTF8.GetBytes("DataVanger.Quarantine.V2");

    public static QuarantineKeyMaterial FromMaster(byte[] master)
        => new(Derive(master, "payload"), Derive(master, "metadata"));

    public static byte[] Derive(byte[] master, string label)
        => HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32, Salt, Encoding.UTF8.GetBytes(label));
}
