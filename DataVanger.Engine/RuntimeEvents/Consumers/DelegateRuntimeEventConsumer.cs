using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.RuntimeEvents;

/// <summary>
/// Adapts a delegate to <see cref="IRuntimeEventConsumer"/>. Useful for
/// tests that want a one-line consumer and for integration code that
/// wires existing logging/reporting sinks without a dedicated class.
///
/// The delegate runs inline on the publishing thread (the pipeline
/// guarantees consumer-failure isolation, so a throwing delegate is
/// recorded as a warning and never crashes the pipeline).
/// </summary>
public sealed class DelegateRuntimeEventConsumer : IRuntimeEventConsumer
{
    private readonly Func<RuntimeSecurityEvent, CancellationToken, ValueTask> _handler;

    public DelegateRuntimeEventConsumer(Action<RuntimeSecurityEvent> handler)
    {
        if (handler is null) throw new ArgumentNullException(nameof(handler));
        _handler = (ev, _) => { handler(ev); return ValueTask.CompletedTask; };
    }

    public DelegateRuntimeEventConsumer(Func<RuntimeSecurityEvent, CancellationToken, ValueTask> handler)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    public ValueTask HandleAsync(RuntimeSecurityEvent runtimeEvent, CancellationToken cancellationToken = default)
        => runtimeEvent is null ? ValueTask.CompletedTask : _handler(runtimeEvent, cancellationToken);
}
