namespace DataVanger.Memory;

/// <summary>
/// Categorises a memory region by its backing storage. Mirrors the Win32
/// MEM_PRIVATE/MEM_IMAGE/MEM_MAPPED taxonomy without requiring a Windows
/// host to enumerate the values.
/// </summary>
public enum MemoryRegionKind
{
    /// <summary>Unknown or not classified yet.</summary>
    Unknown = 0,

    /// <summary>Anonymous private memory (heap, VirtualAlloc, etc.). Most suspicious when executable.</summary>
    Private = 1,

    /// <summary>Memory mapped from a PE image (a loaded DLL/EXE). Normally benign.</summary>
    Image = 2,

    /// <summary>Memory-mapped file or section that is NOT a PE image (e.g. data file).</summary>
    Mapped = 3,
}
