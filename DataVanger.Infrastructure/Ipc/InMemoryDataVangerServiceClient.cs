using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Ipc;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Deterministic in-process IPC client. This is the primary test/development
/// transport: it serializes the request (simulating the wire), enforces the
/// bounded message size, applies the request timeout, honors cancellation, and
/// delegates to an in-process host. Every failure mode becomes a structured
/// response — it never throws for unavailable / oversized / timeout /
/// cancellation.
/// </summary>
public sealed class InMemoryDataVangerServiceClient : IDataVangerServiceClient
{
    private readonly IDataVangerServiceHost _host;
    private readonly IpcOptions _options;
    private readonly ServiceConnectionStatus _status;

    public InMemoryDataVangerServiceClient(
        IDataVangerServiceHost host,
        IpcOptions? options = null,
        ServiceConnectionStatus status = ServiceConnectionStatus.TestHost)
    {
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _options = options ?? IpcOptions.Default;
        _status = status;
    }

    public ServiceConnectionStatus ConnectionStatus => _status;

    public bool IsAvailable =>
        _status is ServiceConnectionStatus.Connected
            or ServiceConnectionStatus.DevelopmentHost
            or ServiceConnectionStatus.TestHost
            or ServiceConnectionStatus.Degraded;

    public async Task<DataVangerResponse> SendAsync(DataVangerRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
            return DataVangerResponse.Error(string.Empty, IpcStatusCode.BadRequest, "Request was null.", "NullRequest");

        // Simulate the wire: serialize and enforce the bounded message size.
        string wire = IpcSerialization.SerializeRequest(request);
        int wireBytes = IpcSerialization.ByteSize(wire);
        if (wireBytes > _options.MaxMessageBytes)
            return DataVangerResponse.Error(
                request.RequestId,
                IpcStatusCode.PayloadTooLarge,
                $"Request ({wireBytes} bytes) exceeds the bounded limit ({_options.MaxMessageBytes} bytes).",
                "PayloadTooLarge");

        if (cancellationToken.IsCancellationRequested)
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Cancelled, "Request was cancelled.", "Cancelled");

        // Faithfully round-trip the envelope to mimic a real transport.
        if (!IpcSerialization.TryDeserializeRequest(wire, out var decoded) || decoded is null)
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.BadRequest, "Request could not be encoded.", "EncodeFailed");

        using var timeoutCts = new CancellationTokenSource(_options.RequestTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        try
        {
            return await _host.HandleAsync(decoded, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
                return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Cancelled, "Request was cancelled.", "Cancelled");

            return DataVangerResponse.Error(
                request.RequestId,
                IpcStatusCode.Timeout,
                $"Request timed out after {_options.RequestTimeout.TotalMilliseconds:F0} ms.",
                "Timeout");
        }
        catch (Exception ex)
        {
            // Defensive: a host-level exception must not crash the UI.
            return DataVangerResponse.Error(
                request.RequestId,
                IpcStatusCode.InternalError,
                $"Unexpected client error: {ex.Message}",
                "ClientInternalError");
        }
    }
}
