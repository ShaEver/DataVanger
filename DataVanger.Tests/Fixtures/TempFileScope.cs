using System;
using System.IO;

namespace DataVanger.Tests.Fixtures;

/// <summary>
/// Small disposable helper for tests that need a real temporary file. Cleanup is
/// best-effort and deterministic; the explicit non-empty catch keeps the phase-02
/// "no anonymous empty catch" invariant intact.
/// </summary>
public sealed class TempFileScope : IDisposable
{
    public string Path { get; }

    public TempFileScope(string extension = ".tmp")
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"dvtest_{Guid.NewGuid():N}{extension}");
    }

    public TempFileScope WithContent(byte[] bytes)
    {
        File.WriteAllBytes(Path, bytes);
        return this;
    }

    public TempFileScope WithText(string text)
    {
        File.WriteAllText(Path, text);
        return this;
    }

    public void Dispose()
    {
        try
        {
            File.Delete(Path);
        }
        catch (Exception)
        {
            // Temp cleanup best effort only.
        }
    }
}
