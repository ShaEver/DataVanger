using System;
using System.Buffers.Binary;
using System.Text;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// One decoded ingest message pushed by the native AMSI provider shim.
/// Every field is a bounded, already-validated value; the content is only a
/// prefix of the scanned buffer (the shim copies at most
/// <see cref="AmsiIngestProtocol.MaxContentBytes"/> bytes).
/// </summary>
public readonly struct AmsiIngestMessage
{
    public AmsiIngestMessage(string appName, string contentName, int pid, ulong session, string content)
    {
        AppName = appName ?? string.Empty;
        ContentName = contentName ?? string.Empty;
        Pid = pid;
        Session = session;
        Content = content ?? string.Empty;
    }

    /// <summary>The AMSI <c>appName</c> (e.g. "PowerShell", "VBScript", "Excel.exe").</summary>
    public string AppName { get; }

    /// <summary>The AMSI <c>contentName</c> (script path / URL / label), possibly empty.</summary>
    public string ContentName { get; }

    /// <summary>Process id of the third-party host that called AMSI. 0 when unknown.</summary>
    public int Pid { get; }

    /// <summary>AMSI session correlation id (opaque), 0 when the host did not supply one.</summary>
    public ulong Session { get; }

    /// <summary>The bounded content prefix the shim forwarded.</summary>
    public string Content { get; }
}

/// <summary>
/// Strict, fixed-layout binary framing for the AMSI ingest pipe.
///
/// The wire format is deliberately trivial so the native C++ shim can emit it
/// with a fixed stack buffer and zero parsing libraries, and so the managed
/// decoder can treat every incoming frame as HOSTILE: it validates the magic,
/// every declared length against a hard cap, and the total frame consistency
/// before touching any content. Anything malformed, truncated, or oversized is
/// rejected (<see cref="TryDecode"/> returns false) and produces no event.
///
/// Layout (little-endian):
/// <code>
///   offset  0 : magic          u8[4]  = { 'D','V','A','1' }
///   offset  4 : pid            u32
///   offset  8 : session        u64
///   offset 16 : appNameLen     u16   (&lt;= MaxNameBytes)
///   offset 18 : contentNameLen u16   (&lt;= MaxNameBytes)
///   offset 20 : contentLen     u32   (&lt;= MaxContentBytes)
///   offset 24 : appName        u8[appNameLen]        (UTF-8)
///             : contentName    u8[contentNameLen]    (UTF-8)
///             : content        u8[contentLen]        (UTF-8)
/// </code>
/// There is exactly one message per pipe connection (the shim connects, writes
/// one frame, and disconnects), so no length-delimited streaming is needed.
/// </summary>
public static class AmsiIngestProtocol
{
    /// <summary>Frame magic: ASCII "DVA1". Bumping the trailing digit versions the format.</summary>
    public static ReadOnlySpan<byte> Magic => "DVA1"u8;

    public const int HeaderBytes = 24;

    /// <summary>Hard cap for the appName/contentName fields.</summary>
    public const int MaxNameBytes = 256;

    /// <summary>
    /// Hard cap for the forwarded content prefix. Matches
    /// <see cref="RuntimeTelemetryEvent.MaxScriptContentLength"/> so a valid frame
    /// never carries more than the event bus will keep.
    /// </summary>
    public const int MaxContentBytes = RuntimeTelemetryEvent.MaxScriptContentLength;

    /// <summary>
    /// Absolute maximum size of any single frame. A read that exceeds this is a
    /// protocol violation and is dropped without allocation beyond the read cap.
    /// </summary>
    public const int MaxFrameBytes = HeaderBytes + (2 * MaxNameBytes) + MaxContentBytes;

    /// <summary>
    /// Validates and decodes a single frame. Returns false (and a default
    /// message) for ANY inconsistency — wrong magic, truncated header/body,
    /// a declared length over its cap, or a total-size mismatch. Never throws.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> frame, out AmsiIngestMessage message)
    {
        message = default;

        if (frame.Length < HeaderBytes || frame.Length > MaxFrameBytes)
            return false;
        if (!frame.Slice(0, 4).SequenceEqual(Magic))
            return false;

        uint pid = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(4, 4));
        ulong session = BinaryPrimitives.ReadUInt64LittleEndian(frame.Slice(8, 8));
        int appNameLen = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(16, 2));
        int contentNameLen = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(18, 2));
        long contentLen = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(20, 4));

        if (appNameLen > MaxNameBytes || contentNameLen > MaxNameBytes || contentLen > MaxContentBytes)
            return false;

        long total = (long)HeaderBytes + appNameLen + contentNameLen + contentLen;
        if (total != frame.Length)
            return false;

        int offset = HeaderBytes;
        string appName = Utf8(frame.Slice(offset, appNameLen));
        offset += appNameLen;
        string contentName = Utf8(frame.Slice(offset, contentNameLen));
        offset += contentNameLen;
        string content = Utf8(frame.Slice(offset, (int)contentLen));

        message = new AmsiIngestMessage(appName, contentName, (int)pid, session, content);
        return true;
    }

    /// <summary>
    /// Encodes a frame. Used by tests and as the reference the native shim
    /// mirrors. Over-long strings/content are truncated to their caps so the
    /// output is always a valid frame.
    /// </summary>
    public static byte[] Encode(string appName, string contentName, int pid, ulong session, string content)
    {
        byte[] appBytes = ClampUtf8(appName, MaxNameBytes);
        byte[] nameBytes = ClampUtf8(contentName, MaxNameBytes);
        byte[] contentBytes = ClampUtf8(content, MaxContentBytes);

        var frame = new byte[HeaderBytes + appBytes.Length + nameBytes.Length + contentBytes.Length];
        var span = frame.AsSpan();

        Magic.CopyTo(span);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(4, 4), unchecked((uint)pid));
        BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(8, 8), session);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(16, 2), (ushort)appBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(18, 2), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(20, 4), (uint)contentBytes.Length);

        int offset = HeaderBytes;
        appBytes.CopyTo(span.Slice(offset)); offset += appBytes.Length;
        nameBytes.CopyTo(span.Slice(offset)); offset += nameBytes.Length;
        contentBytes.CopyTo(span.Slice(offset));

        return frame;
    }

    private static string Utf8(ReadOnlySpan<byte> bytes)
        => bytes.IsEmpty ? string.Empty : Encoding.UTF8.GetString(bytes);

    private static byte[] ClampUtf8(string? value, int maxBytes)
    {
        if (string.IsNullOrEmpty(value)) return Array.Empty<byte>();
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length <= maxBytes) return bytes;

        // Truncate on a UTF-8 boundary so we never split a multi-byte sequence.
        int end = maxBytes;
        while (end > 0 && (bytes[end] & 0xC0) == 0x80) end--;
        Array.Resize(ref bytes, end);
        return bytes;
    }
}
