using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Incremental SHA-256 helper used by the hashing stage.
///
/// Two properties matter for the deep pipeline:
///
///   1. It never materialises the whole file in memory. Buffers are rented
///      from <see cref="ArrayPool{T}"/> and recycled, so a 4&#160;GB archive
///      entry costs the same as a 4&#160;KB script.
///   2. Cancellation is honored on every read so a stuck IO does not block
///      shutdown beyond one buffer's worth of work.
/// </summary>
public static class StreamHasher
{
    private const int DefaultBufferSize = 81_920; // matches Stream.CopyTo default

    public static async Task<string?> ComputeSha256Async(
        Stream stream,
        long maxBytes,
        CancellationToken cancellationToken,
        int bufferSize = DefaultBufferSize)
    {
        if (stream is null) return null;
        if (bufferSize < 4_096) bufferSize = 4_096;

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        long total = 0;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int n;
                try
                {
                    n = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                }
                catch (IOException)
                {
                    return null;
                }

                if (n <= 0) break;
                total += n;
                if (maxBytes > 0 && total > maxBytes) return null;
                sha.AppendData(buffer, 0, n);
            }
            return Convert.ToHexString(sha.GetHashAndReset());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: false);
        }
    }
}
