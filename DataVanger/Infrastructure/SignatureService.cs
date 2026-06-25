using DataVanger.Core;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// Thin adapter that exposes <see cref="SignatureDatabase"/> behind
/// <see cref="ISignatureService"/>. Lets the detection modules depend on the
/// abstraction instead of the concrete database type.
/// </summary>
public sealed class SignatureService : ISignatureService
{
    private readonly SignatureDatabase _db;

    public SignatureService(SignatureDatabase db) { _db = db; }

    public bool IsKnownMalicious(string sha256) => _db.IsKnownMalicious(sha256);
    public bool IsKnownSafe(string sha256) => _db.IsKnownSafe(sha256);
    public int TotalHashes => _db.TotalHashes;
}
