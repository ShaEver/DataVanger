using System.Runtime.CompilerServices;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Side-table attaching per-root-archive guards (recursion + zip bomb) to a
/// <see cref="ScanWorkItem"/> without polluting its public surface.
///
/// Implemented with <see cref="ConditionalWeakTable{TKey,TValue}"/> so guards
/// vanish when no work item still references the root archive — i.e. the
/// pipeline never leaks memory across scans.
/// </summary>
internal static class ScanWorkItemGuards
{
    private sealed class Pair
    {
        public RecursionGuard Recursion { get; }
        public ZipBombGuard ZipBomb { get; }
        public Pair(RecursionGuard r, ZipBombGuard z) { Recursion = r; ZipBomb = z; }
    }

    private static readonly ConditionalWeakTable<ScanWorkItem, Pair> s_table = new();

    public static void Attach(ScanWorkItem item, RecursionGuard recursion, ZipBombGuard zipBomb)
    {
        if (item is null) return;
        s_table.AddOrUpdate(item, new Pair(recursion, zipBomb));
    }

    public static bool TryGet(ScanWorkItem item, out RecursionGuard? recursion, out ZipBombGuard? zipBomb)
    {
        if (s_table.TryGetValue(item, out var pair))
        {
            recursion = pair.Recursion;
            zipBomb   = pair.ZipBomb;
            return true;
        }
        recursion = null;
        zipBomb = null;
        return false;
    }
}
