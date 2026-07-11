using System;
using System.IO;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Binary codec for the authenticated quarantine payload file (".qbin").
///
/// Layout:
///   [4]  magic  'Q','B','I','N'
///   [1]  format version (2)
///   [1]  nonce length
///   [1]  tag length
///   [1]  reserved (0)
///   [n]  nonce
///   [t]  tag
///   [..] ciphertext (remainder)
///
/// A truncated or malformed file is reported by returning null from
/// <see cref="TryDecode"/> — never by throwing — so the service can translate
/// it into a structured "corrupt payload" result.
/// </summary>
public static class QuarantinePayloadCodec
{
    private static readonly byte[] Magic = { (byte)'Q', (byte)'B', (byte)'I', (byte)'N' };
    private const byte FormatVersion = 2;

    public static byte[] Encode(QuarantineEncryptedPayload payload)
    {
        if (payload is null) throw new ArgumentNullException(nameof(payload));
        if (payload.Nonce.Length > 255 || payload.Tag.Length > 255)
            throw new ArgumentOutOfRangeException(nameof(payload), "Nonce/tag too large for payload header.");

        using var ms = new MemoryStream();
        ms.Write(Magic, 0, Magic.Length);
        ms.WriteByte(FormatVersion);
        ms.WriteByte((byte)payload.Nonce.Length);
        ms.WriteByte((byte)payload.Tag.Length);
        ms.WriteByte(0);
        ms.Write(payload.Nonce, 0, payload.Nonce.Length);
        ms.Write(payload.Tag, 0, payload.Tag.Length);
        ms.Write(payload.CipherText, 0, payload.CipherText.Length);
        return ms.ToArray();
    }

    /// <summary>Returns the decoded payload, or null if the bytes are malformed/truncated.</summary>
    public static QuarantineEncryptedPayload? TryDecode(byte[] raw, string algorithm)
    {
        if (raw is null || raw.Length < 8) return null;
        if (raw[0] != Magic[0] || raw[1] != Magic[1] || raw[2] != Magic[2] || raw[3] != Magic[3]) return null;
        if (raw[4] != FormatVersion) return null;

        int nonceLen = raw[5];
        int tagLen = raw[6];
        int offset = 8;
        if (nonceLen <= 0 || tagLen <= 0) return null;
        if (raw.Length < offset + nonceLen + tagLen) return null;

        var nonce = new byte[nonceLen];
        Array.Copy(raw, offset, nonce, 0, nonceLen);
        offset += nonceLen;

        var tag = new byte[tagLen];
        Array.Copy(raw, offset, tag, 0, tagLen);
        offset += tagLen;

        int cipherLen = raw.Length - offset;
        var cipher = new byte[cipherLen];
        Array.Copy(raw, offset, cipher, 0, cipherLen);

        return new QuarantineEncryptedPayload(nonce, cipher, tag, algorithm);
    }
}
