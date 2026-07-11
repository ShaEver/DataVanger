using System;
using DataVanger.Memory.Readers;

namespace DataVanger.Memory;

/// <summary>
/// Constructs an <see cref="IMemoryScanner"/> appropriate for the host.
/// In this build we never attach a real OS reader automatically — the
/// production reader would live behind a separate Windows-only package
/// and be injected by the host. Default factory output is always safe
/// (no-op) which is exactly what we want for CI, tests, and the
/// non-elevated execution path.
/// </summary>
public static class MemoryScannerFactory
{
    public static IMemoryScanner CreateSafeDefault(Action<string>? diagnostics = null)
        => new MemoryScannerEngine(NullMemoryReader.Instance, diagnostics: diagnostics);

    public static IMemoryScanner CreateFromReader(IMemoryReader reader, Action<string>? diagnostics = null)
        => new MemoryScannerEngine(reader ?? NullMemoryReader.Instance, diagnostics: diagnostics);
}
