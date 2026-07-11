namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Optional sink that receives protected-file activity evidence as it is
/// generated. Useful for reporting/forensics wiring and for deterministic
/// tests.
///
/// A sink is a passive observer. It MUST NOT take destructive action in
/// response to evidence (no quarantine, no kill, no block, no file-write
/// blocking). The monitor isolates sink failures: a throwing sink never
/// crashes the monitor.
/// </summary>
public interface IProtectedFilesActivityEvidenceSink
{
    void OnEvidence(ProtectedFilesActivityEvidence evidence);
}
