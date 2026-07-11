namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// Optional sink that receives behavioral evidence as it is generated.
/// Useful for reporting/forensics wiring and for deterministic tests.
///
/// A sink is a passive observer. It MUST NOT take destructive action in
/// response to evidence (no quarantine, no kill, no block). The binding
/// isolates sink failures: a throwing sink never crashes the binding.
/// </summary>
public interface IBehavioralRuntimeEvidenceSink
{
    void OnEvidence(BehavioralRuntimeEvidence evidence);
}
