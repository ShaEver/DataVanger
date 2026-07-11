using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Ipc;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Local-only named-pipe IPC client. Connects to the resident service over a
/// product-specific local pipe, sends a single length-prefixed request, and
/// reads a single length-prefixed response.
///
/// Graceful degradation: when the service pipe is absent, the connect attempt
/// fails fast and a structured <see cref="IpcStatusCode.ServiceUnavailable"/>
/// response is returned — never an exception. The connection is local-only:
/// the server name is always "." and there is no TCP/HTTP/socket fallback.
///
/// Tests do NOT require this transport; the in-memory client is the primary
/// deterministic test target.
/// </summary>
public sealed class NamedPipeDataVangerServiceClient : IDataVangerServiceClient
{
    private readonly IpcOptions _options;

    public NamedPipeDataVangerServiceClient(IpcOptions? options = null)
    {
        _options = options ?? IpcOptions.Default;
    }

    // The client cannot know connectivity without attempting a connection; it
    // reports Unknown until a request is made. Each request reflects the real
    // outcome in the response status code.
    public ServiceConnectionStatus ConnectionStatus => ServiceConnectionStatus.Unknown;

    public bool IsAvailable => false;

    public async Task<DataVangerResponse> SendAsync(DataVangerRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
            return DataVangerResponse.Error(string.Empty, IpcStatusCode.BadRequest, "Request was null.", "NullRequest");

        string wire = IpcSerialization.SerializeRequest(request);
        byte[] payload = Encoding.UTF8.GetBytes(wire);
        if (payload.Length > _options.MaxMessageBytes)
            return DataVangerResponse.Error(
                request.RequestId,
                IpcStatusCode.PayloadTooLarge,
                $"Request ({payload.Length} bytes) exceeds the bounded limit ({_options.MaxMessageBytes} bytes).",
                "PayloadTooLarge");

        if (cancellationToken.IsCancellationRequested)
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Cancelled, "Request was cancelled.", "Cancelled");

        using var timeoutCts = new CancellationTokenSource(_options.RequestTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        // Local-only: server name is always ".".
        using var pipe = new NamedPipeClientStream(".", _options.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        try
        {
            await pipe.ConnectAsync(linked.Token).ConfigureAwait(false);

            await NamedPipeFraming.WriteFrameAsync(pipe, payload, linked.Token).ConfigureAwait(false);
            byte[]? responseBytes = await NamedPipeFraming.ReadFrameAsync(pipe, _options.MaxMessageBytes, linked.Token).ConfigureAwait(false);

            if (responseBytes is null)
                return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported, "Service closed the pipe without responding.", "NoResponse");

            string responseJson = Encoding.UTF8.GetString(responseBytes);
            if (!IpcSerialization.TryDeserializeResponse(responseJson, out var response) || response is null)
                return DataVangerResponse.Error(request.RequestId, IpcStatusCode.InternalError, "Malformed response from service.", "MalformedResponse");

            return response;
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
                return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Cancelled, "Request was cancelled.", "Cancelled");

            // Connect/read timed out — treat as unreachable for the UI.
            return DataVangerResponse.Error(
                request.RequestId,
                IpcStatusCode.ServiceUnavailable,
                "The resident DataVanger service could not be reached (timeout).",
                "ServiceUnavailable");
        }
        catch (InvalidDataException ex)
        {
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.InternalError, $"Framing error: {ex.Message}", "FramingError");
        }
        catch (IOException)
        {
            return DataVangerResponse.Error(
                request.RequestId,
                IpcStatusCode.ServiceUnavailable,
                "The resident DataVanger service could not be reached.",
                "ServiceUnavailable");
        }
        catch (Exception ex)
        {
            // Includes platforms/configurations where named pipes are unsupported.
            return DataVangerResponse.Error(
                request.RequestId,
                IpcStatusCode.ServiceUnavailable,
                $"Named-pipe transport unavailable: {ex.Message}",
                "ServiceUnavailable");
        }
    }
}
