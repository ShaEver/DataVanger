using System;
using Xunit;

// Phase 02B — explicit Windows-only test skipping.
//
// Vanilla xUnit guards like `if (!OperatingSystem.IsWindows()) return;` make a
// Windows-only test SILENTLY PASS on other platforms, which overstates
// coverage. These attributes set the xUnit Skip reason at discovery time so
// non-Windows runs report the test as SKIPPED with an explicit reason — the
// phase requirement: "non-Windows skips that prove the test is intentionally
// Windows-only".
public sealed class WindowsOnlyFactAttribute : FactAttribute
{
    public WindowsOnlyFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Windows-only: exercises Windows named-pipe security descriptors (ACL/DACL).";
    }
}

public sealed class WindowsOnlyTheoryAttribute : TheoryAttribute
{
    public WindowsOnlyTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Windows-only: exercises Windows named-pipe security descriptors (ACL/DACL).";
    }
}
