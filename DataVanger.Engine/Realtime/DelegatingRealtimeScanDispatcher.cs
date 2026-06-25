using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Realtime;

namespace DataVanger.Engine.Realtime;

/// <summary>
/// Dispatcher implementation that forwards each request to a caller-
/// supplied scan delegate. This keeps the realtime stack decoupled
/// from any concrete scan engine — production wires in the existing
/// <c>ScanEngine</c> via a thin lambda; tests inject deterministic
/// behavior without touching real binaries.
///
/// The dispatcher itself:
///   - Catches any exception thrown by the delegate and converts it to
///     a Failed result (never to a malware verdict).
///   - Honors cancellation.
///   - Stamps <see cref="RealtimeScanResult.CompletedAtUtc"/> using a
///     caller-supplied clock so tests stay deterministic.
/// </summary>
public sealed class DelegatingRealtimeScanDispatcher : IRealtimeScanDispatcher
{
    private readonly Func<RealtimeScanRequest, CancellationToken, Task<RealtimeScanResult>> _scan;
    private readonly Func<DateTimeOffset> _utcNow;

    public DelegatingRealtimeScanDispatcher(
        Func<RealtimeScanRequest, CancellationToken, Task<RealtimeScanResult>> scan,
        Func<DateTimeOffset>? utcNow = null)
    {
        _scan = scan ?? throw new ArgumentNullException(nameof(scan));
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public async Task<RealtimeScanResult> DispatchAsync(RealtimeScanRequest request, CancellationToken cancellationToken)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var result = await _scan(request, cancellationToken).ConfigureAwait(false);
            if (result is null)
            {
                return new RealtimeScanResult
                {
                    Path = request.Path,
                    Verdict = RealtimeProtectionVerdict.Indeterminate,
                    IsConfirmedMalware = false,
                    Failed = true,
                    FailureReason = "scan delegate returned null",
                    CompletedAtUtc = _utcNow(),
                };
            }
            // Defensive: never trust caller-side IsConfirmedMalware if
            // the verdict does not match. Anti-FP belt-and-braces.
            var safeConfirmed = result.IsConfirmedMalware
                                && result.Verdict == RealtimeProtectionVerdict.ConfirmedMalware;
            return new RealtimeScanResult
            {
                Path = result.Path,
                Verdict = result.Verdict,
                IsConfirmedMalware = safeConfirmed,
                FromCache = result.FromCache,
                Failed = result.Failed,
                FailureReason = result.FailureReason,
                CompletedAtUtc = result.CompletedAtUtc == default ? _utcNow() : result.CompletedAtUtc,
                Message = result.Message,
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new RealtimeScanResult
            {
                Path = request.Path,
                Verdict = RealtimeProtectionVerdict.Indeterminate,
                IsConfirmedMalware = false,
                Failed = true,
                FailureReason = ex.Message,
                CompletedAtUtc = _utcNow(),
            };
        }
    }
}
