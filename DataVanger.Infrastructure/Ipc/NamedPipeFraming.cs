using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Minimal length-prefixed framing for the local named-pipe transport. Each
/// message is a 4-byte big-endian UTF-8 byte length followed by the payload.
/// Reads enforce a hard maximum so an oversized or malformed frame is rejected
/// instead of allocating unbounded memory.
/// </summary>
internal static class NamedPipeFraming
{
    public static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await stream.WriteAsync(header.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
        if (payload.Length > 0)
            await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one frame. Returns null on a clean end-of-stream. Throws
    /// <see cref="InvalidDataException"/> for a frame larger than
    /// <paramref name="maxBytes"/> or a truncated frame.
    /// </summary>
    public static async Task<byte[]?> ReadFrameAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        int headerRead = await ReadExactAsync(stream, header, 4, cancellationToken).ConfigureAwait(false);
        if (headerRead == 0) return null; // clean EOF
        if (headerRead < 4) throw new InvalidDataException("Truncated IPC frame header.");

        int length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length < 0 || length > maxBytes)
            throw new InvalidDataException($"IPC frame length {length} is out of bounds (max {maxBytes}).");

        if (length == 0) return Array.Empty<byte>();

        var payload = new byte[length];
        int bodyRead = await ReadExactAsync(stream, payload, length, cancellationToken).ConfigureAwait(false);
        if (bodyRead < length) throw new InvalidDataException("Truncated IPC frame body.");
        return payload;
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < count)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total, count - total), cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}
