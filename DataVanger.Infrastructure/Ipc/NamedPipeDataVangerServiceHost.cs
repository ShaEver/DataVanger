using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Ipc;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Local-only named-pipe IPC host. Listens on a product-specific local pipe and
/// serves requests by delegating to an inner host (the service command router).
///
/// Safety / development properties:
///   - Local-only: a <see cref="NamedPipeServerStream"/>, never a TCP/HTTP
///     listener.
///   - Bounded: frames are size-capped via <see cref="IpcOptions.MaxMessageBytes"/>.
///   - Cancellation-safe: every wait honors the supplied token; there is no
///     <c>while (true)</c> loop. <see cref="RunAsync"/> is opt-in and exits as
///     soon as cancellation is requested.
///   - NOT auto-started: nothing in this phase spins this host up during
///     <c>dotnet build</c>, <c>dotnet run</c>, or tests.
///   - ACL-hardened on Windows: when <see cref="IpcOptions.HardenPipeAcl"/> is
///     set (the default), the server pipe is created with a least-privilege
///     security descriptor (see <see cref="IpcPipeSecurity"/>) so only the
///     creating user, Local System, and explicitly configured local principals
///     may connect. Everyone/Network/Anonymous are not granted. On non-Windows
///     hosts a plain local pipe is used. This is connection-level defense in
///     depth; it does NOT change payload validation, framing, or serialization.
/// </summary>
public sealed class NamedPipeDataVangerServiceHost
{
    private readonly IDataVangerServiceHost _inner;
    private readonly IpcOptions _options;

    public NamedPipeDataVangerServiceHost(IDataVangerServiceHost inner, IpcOptions? options = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _options = options ?? IpcOptions.Default;
    }

    /// <summary>
    /// Accepts and serves exactly one connection/request, then returns. Used as
    /// the single-shot primitive; safe to call repeatedly by a caller-owned
    /// loop. Returns false when cancellation interrupts the wait.
    /// </summary>
    public async Task<bool> ProcessNextAsync(CancellationToken cancellationToken)
    {
        using var server = CreateServerStream();

        try
        {
            await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }

        try
        {
            byte[]? requestBytes = await NamedPipeFraming.ReadFrameAsync(server, _options.MaxMessageBytes, cancellationToken).ConfigureAwait(false);
            DataVangerResponse response;

            if (requestBytes is null)
            {
                return true; // client disconnected without sending
            }

            string requestJson = Encoding.UTF8.GetString(requestBytes);
            if (!IpcSerialization.TryDeserializeRequest(requestJson, out var request) || request is null)
            {
                response = DataVangerResponse.Error(string.Empty, IpcStatusCode.BadRequest, "Malformed request envelope.", "MalformedRequest");
            }
            else
            {
                response = await _inner.HandleAsync(request, cancellationToken).ConfigureAwait(false);
            }

            byte[] responseBytes = Encoding.UTF8.GetBytes(IpcSerialization.SerializeResponse(response));
            if (responseBytes.Length <= _options.MaxMessageBytes)
                await NamedPipeFraming.WriteFrameAsync(server, responseBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            // Oversized/truncated frame — drop the connection without crashing.
        }
        catch (IOException)
        {
            // Broken pipe — drop the connection without crashing.
        }
        finally
        {
            if (server.IsConnected)
            {
                try { server.Disconnect(); } catch { /* best-effort */ }
            }
        }

        return true;
    }

    /// <summary>
    /// Creates the server pipe. On Windows with ACL hardening enabled, the pipe
    /// carries a least-privilege security descriptor restricting which local
    /// principals may connect; otherwise a plain local pipe is used. All other
    /// pipe semantics (name, direction, instance cap, transmission mode, options)
    /// are identical in both paths.
    ///
    /// Phase 02B fail-closed gate: when <see cref="IpcOptions.RequireAclHardening"/>
    /// is set and the ACL-hardened path is unavailable (unsupported platform or
    /// hardening disabled), this THROWS instead of opening an unrestricted pipe.
    /// Any failure inside ACL construction itself also propagates — there is no
    /// catch that could fall back to an insecure pipe.
    /// </summary>
    private NamedPipeServerStream CreateServerStream()
    {
        if (_options.HardenPipeAcl && OperatingSystem.IsWindows())
            return IpcPipeSecurity.CreateServerStream(_options);

        if (_options.RequireAclHardening)
            throw new InvalidOperationException(
                "IPC ACL hardening is required but unavailable " +
                (IpcPipeSecurity.IsSupported
                    ? "(HardenPipeAcl is disabled)."
                    : "(platform does not support pipe security descriptors).") +
                " Refusing to open an unrestricted pipe.");

        return new NamedPipeServerStream(
            _options.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    /// <summary>
    /// Opt-in serve loop. Exits as soon as cancellation is requested. Never used
    /// by tests and never auto-started in this phase. A single consumer-driven
    /// host instance — no aggressive spin, no background detachment.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            bool served = await ProcessNextAsync(cancellationToken).ConfigureAwait(false);
            if (!served) break;
        }
    }
}
