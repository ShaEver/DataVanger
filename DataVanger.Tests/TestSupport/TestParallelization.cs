// The legacy DataVanger.Tests runner (Program.cs) executed strictly sequentially
// in a single process. The migrated suite preserves that model: the legacy checks
// run as one large sequential [Fact] (LegacyParityTests) that relies on process-wide
// and static state (temp directories, scheduler stores, runtime event pipelines,
// static caches). Disabling xUnit's cross-class parallelization keeps execution
// single-threaded and deterministic — exactly matching the original runner — and
// prevents any flakiness between the legacy suite and the focused anti-FP class.
[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]
