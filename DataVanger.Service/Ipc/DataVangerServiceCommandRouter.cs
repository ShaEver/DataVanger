using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Service-side IPC command router. Validates each request against the
/// allowlist and bounded size policy, then maps the command category to a safe
/// handler.
///
/// Guarantees:
///   - Unknown commands return a structured <see cref="IpcStatusCode.UnknownCommand"/> error.
///   - Malformed payloads return a structured <see cref="IpcStatusCode.BadRequest"/> error.
///   - Unsupported (but recognized) commands return a structured <see cref="IpcStatusCode.Unsupported"/> error.
///   - Handler exceptions are captured and returned as <see cref="IpcStatusCode.InternalError"/> — never thrown across the boundary.
///   - Cancellation is honored and surfaced as <see cref="IpcStatusCode.Cancelled"/>.
///   - No admin privileges, no installed service, and no network are required.
/// </summary>
public sealed class DataVangerServiceCommandRouter : IDataVangerServiceHost
{
    private readonly IpcOptions _options;
    private readonly StatusCommandHandler _status;
    private readonly ProtectionCommandHandler _protection;
    private readonly ScanCommandHandler _scan;
    private readonly QuarantineCommandHandler _quarantine;
    private readonly RemediationCommandHandler _remediation;
    private readonly UpdateCommandHandler _update;
    private readonly EventQueryCommandHandler _events;
    private readonly DiagnosticsCommandHandler _diagnostics;

    public DataVangerServiceCommandRouter(
        DataVangerServiceCommandContext context,
        IpcOptions? options = null)
    {
        if (context is null) throw new ArgumentNullException(nameof(context));
        _options = options ?? IpcOptions.Default;
        _status = new StatusCommandHandler(context);
        _protection = new ProtectionCommandHandler(context);
        _scan = new ScanCommandHandler(context);
        _quarantine = new QuarantineCommandHandler(context);
        _remediation = new RemediationCommandHandler(context);
        _update = new UpdateCommandHandler(context);
        _events = new EventQueryCommandHandler(context);
        _diagnostics = new DiagnosticsCommandHandler(context);
    }

    public async Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken = default)
    {
        // Structured validation: null envelope, allowlist, bounded size.
        var validation = IpcSecurityPolicy.ValidateRequest(request, _options);
        if (!validation.IsValid)
        {
            string requestId = request?.RequestId ?? string.Empty;
            return DataVangerResponse.Error(requestId, validation.StatusCode, validation.Message, validation.ErrorCode);
        }

        if (cancellationToken.IsCancellationRequested)
            return DataVangerResponse.Error(request!.RequestId, IpcStatusCode.Cancelled, "Request was cancelled.", "Cancelled");

        var category = DataVangerCommandCatalog.CategoryOf(request!.CommandType);

        try
        {
            return category switch
            {
                DataVangerCommandCategory.Status => await _status.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.Configuration => await _status.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.ProtectionControl => await _protection.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.Scan => await _scan.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.Quarantine => await _quarantine.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.Remediation => await _remediation.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.Update => await _update.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.EventQuery => await _events.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                DataVangerCommandCategory.Diagnostics => await _diagnostics.HandleAsync(request, cancellationToken).ConfigureAwait(false),
                _ => DataVangerResponse.Error(request.RequestId, IpcStatusCode.UnknownCommand,
                    $"No handler is registered for command '{request.CommandType}'.", "NoHandler"),
            };
        }
        catch (OperationCanceledException)
        {
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Cancelled, "Request was cancelled.", "Cancelled");
        }
        catch (Exception ex)
        {
            // A handler fault must never crash the service or the UI.
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.InternalError,
                $"Command handler raised an unexpected error: {ex.Message}", "HandlerException");
        }
    }
}
