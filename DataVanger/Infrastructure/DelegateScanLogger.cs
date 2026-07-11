using System;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// <see cref="IScanLogger"/> that forwards every message to a user-supplied
/// <see cref="Action{String}"/>. Used for backwards compatibility with the
/// pre-refactor engine API that took a plain log delegate.
///
/// All methods swallow their own failures so the logger can never crash a scan.
/// </summary>
public sealed class DelegateScanLogger : IScanLogger
{
    private readonly Action<string> _sink;

    public DelegateScanLogger(Action<string> sink) { _sink = sink ?? (_ => { }); }

    public void Info(string message)
    {
        try { _sink(message); } catch (Exception) { /* Logger sink must never throw back to callers - swallow intentionally. */ }
    }

    public void Warn(string message)
    {
        try { _sink("[WARN] " + message); } catch (Exception) { /* Logger sink must never throw back to callers - swallow intentionally. */ }
    }

    public void Error(string message, Exception? ex = null)
    {
        try { _sink("[ERRO] " + message + (ex == null ? "" : " — " + ex.Message)); } catch (Exception) { /* Logger sink must never throw back to callers - swallow intentionally. */ }
    }

    public void SkippedFile(string path, string reason)
    {
        try { _sink($"[skip] {reason}: {path}"); } catch (Exception) { /* Logger sink must never throw back to callers - swallow intentionally. */ }
    }

    public void ModuleFailure(string moduleName, string path, Exception ex)
    {
        try { _sink($"[module {moduleName}] falha em {path}: {ex.Message}"); } catch (Exception) { /* Logger sink must never throw back to callers - swallow intentionally. */ }
    }
}
