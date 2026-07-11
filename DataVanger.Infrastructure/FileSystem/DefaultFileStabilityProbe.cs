using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Default user-mode file stability probe.
///
/// Behavior:
///   - Verifies the path exists and is not a directory.
///   - Enforces the real-time size cap (TooLarge => not scanned in
///     real time; manual / deep scan remains free to inspect).
///   - Opens the file with FileShare.ReadWrite|Delete and confirms the
///     file is reachable WITHOUT locking it.
///   - Samples Length + LastWriteTime twice with a configurable delay
///     and only returns Stable when both observations match.
///   - On timeout, returns Locked / Unavailable / NotFound — never
///     throws (except <see cref="OperationCanceledException"/>).
///   - Honors cancellation between samples.
///
/// Timeouts use wall-clock time (<see cref="Environment.TickCount64"/>)
/// because the underlying <see cref="Task.Delay(TimeSpan)"/> also uses
/// wall-clock time — pairing them keeps the probe terminating even
/// under a fake logical clock.
///
/// Safety guarantees:
///   - Never holds a file open across awaits.
///   - Never blocks installers, browsers, editors, compilers, or build
///     tools (FileShare.ReadWrite|Delete on a brief open).
/// </summary>
public sealed class DefaultFileStabilityProbe : IFileStabilityProbe
{
    private readonly TimeSpan _timeout;
    private readonly TimeSpan _pollInterval;

    public DefaultFileStabilityProbe(TimeSpan timeout, TimeSpan pollInterval)
    {
        if (timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
        if (pollInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(pollInterval));
        _timeout = timeout;
        _pollInterval = pollInterval;
    }

    public async Task<FileStabilityResult> ProbeAsync(string path, long maxSizeBytes, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new FileStabilityResult { Outcome = FileStabilityOutcome.NotFound, Reason = "empty path" };

        var deadlineTicks = Environment.TickCount64 + (long)_timeout.TotalMilliseconds;
        FileStabilityOutcome lastOutcome = FileStabilityOutcome.Unavailable;
        string? lastReason = null;
        long? previousLength = null;
        DateTimeOffset? previousLastWrite = null;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (Directory.Exists(path))
                    return new FileStabilityResult { Outcome = FileStabilityOutcome.IsDirectory };

                if (!File.Exists(path))
                {
                    lastOutcome = FileStabilityOutcome.NotFound;
                    lastReason = "file does not exist";
                }
                else
                {
                    var info = new FileInfo(path);
                    if (maxSizeBytes > 0 && info.Length > maxSizeBytes)
                    {
                        return new FileStabilityResult
                        {
                            Outcome = FileStabilityOutcome.TooLarge,
                            Length = info.Length,
                            LastWriteUtc = info.LastWriteTimeUtc,
                            Reason = $"file size {info.Length} exceeds realtime cap {maxSizeBytes}",
                        };
                    }

                    try
                    {
                        using var stream = new FileStream(
                            path,
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete,
                            bufferSize: 1,
                            useAsync: false);
                        lastOutcome = FileStabilityOutcome.Stable;
                        lastReason = null;
                    }
                    catch (IOException ioex)
                    {
                        lastOutcome = FileStabilityOutcome.Locked;
                        lastReason = ioex.Message;
                    }
                    catch (UnauthorizedAccessException uex)
                    {
                        lastOutcome = FileStabilityOutcome.Unavailable;
                        lastReason = uex.Message;
                    }

                    if (lastOutcome == FileStabilityOutcome.Stable)
                    {
                        var currentLength = info.Length;
                        var currentLastWrite = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
                        if (previousLength.HasValue
                            && previousLength.Value == currentLength
                            && previousLastWrite.HasValue
                            && previousLastWrite.Value == currentLastWrite)
                        {
                            return new FileStabilityResult
                            {
                                Outcome = FileStabilityOutcome.Stable,
                                Length = currentLength,
                                LastWriteUtc = currentLastWrite,
                            };
                        }
                        previousLength = currentLength;
                        previousLastWrite = currentLastWrite;
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                lastOutcome = FileStabilityOutcome.Unavailable;
                lastReason = ex.Message;
            }

            if (Environment.TickCount64 >= deadlineTicks)
            {
                return new FileStabilityResult
                {
                    Outcome = lastOutcome,
                    Length = previousLength ?? -1,
                    LastWriteUtc = previousLastWrite,
                    Reason = lastReason ?? "stability timeout",
                };
            }

            await Task.Delay(_pollInterval, cancellationToken).ConfigureAwait(false);
        }
    }
}
