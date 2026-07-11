using System;

namespace DataVanger.Memory;

/// <summary>
/// Memory page protection flags as a portable abstraction over Win32
/// PAGE_* constants. Kept platform-neutral so non-Windows hosts (tests,
/// CI) can construct fake regions without depending on Win32.
/// </summary>
[Flags]
public enum MemoryProtection
{
    None    = 0,
    Read    = 1 << 0,
    Write   = 1 << 1,
    Execute = 1 << 2,
    Guard   = 1 << 3,
    NoCache = 1 << 4,
}

public static class MemoryProtectionExtensions
{
    public static bool IsExecutable(this MemoryProtection p) => (p & MemoryProtection.Execute) != 0;
    public static bool IsWritable(this MemoryProtection p) => (p & MemoryProtection.Write) != 0;
    public static bool IsReadable(this MemoryProtection p) => (p & MemoryProtection.Read) != 0;
    public static bool IsRwx(this MemoryProtection p)
        => p.IsReadable() && p.IsWritable() && p.IsExecutable();
    public static bool IsRx(this MemoryProtection p)
        => p.IsReadable() && p.IsExecutable() && !p.IsWritable();

    public static string Describe(this MemoryProtection p)
    {
        if (p == MemoryProtection.None) return "NoAccess";
        Span<char> rwx = stackalloc char[3];
        rwx[0] = p.IsReadable() ? 'R' : '-';
        rwx[1] = p.IsWritable() ? 'W' : '-';
        rwx[2] = p.IsExecutable() ? 'X' : '-';
        return new string(rwx);
    }
}
