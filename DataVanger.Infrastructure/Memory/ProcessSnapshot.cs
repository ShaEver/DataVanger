using System;
using System.Collections.Generic;

namespace DataVanger.Memory;

/// <summary>
/// Minimal, immutable snapshot of a process from the memory scanner's
/// point of view. Holds just enough to drive correlation (pid, name,
/// signer trust, accessibility) without locking handles.
/// </summary>
public sealed class ProcessSnapshot
{
    public ProcessSnapshot(
        int processId,
        string processName,
        string imagePath = "",
        bool isSigned = false,
        bool isAccessible = true,
        bool isSystemProtected = false,
        int parentProcessId = 0)
    {
        ProcessId = processId;
        ProcessName = (processName ?? "").Trim().ToLowerInvariant();
        ImagePath = imagePath ?? "";
        IsSigned = isSigned;
        IsAccessible = isAccessible;
        IsSystemProtected = isSystemProtected;
        ParentProcessId = parentProcessId;
    }

    public int ProcessId { get; }
    public int ParentProcessId { get; }
    public string ProcessName { get; }
    public string ImagePath { get; }
    public bool IsSigned { get; }

    /// <summary>True if the scanner could open the process; false means access denied / exited.</summary>
    public bool IsAccessible { get; }

    /// <summary>True for PPL/protected processes that we should treat with extra restraint.</summary>
    public bool IsSystemProtected { get; }

    public override string ToString() => $"{ProcessName}({ProcessId})";
}
