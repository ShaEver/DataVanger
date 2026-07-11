// Shared assertion shim for the decomposed legacy parity tests (phase 09).
//
// Behaviourally identical to the original private Assert(bool, string) used inside
// LegacyParityTests: it delegates to Xunit.Assert.True(condition, message) so the
// failure condition AND the failure message are preserved verbatim. Centralising it
// here lets the per-subsystem test classes (and LegacyParityTests itself) share one
// shim instead of duplicating it.
internal static class LegacyAssert
{
    public static void True(bool condition, string message) => Xunit.Assert.True(condition, message);
}
