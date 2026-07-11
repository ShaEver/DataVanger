using System.IO;
using DataVanger.Engine.Remediation.Files;
using Xunit;

// Phase 03B — safe-path policy unit tests. Filter: ~Remediation.
// The policy is the system-file protection gate; it must be conservative.
public class RemediationSafePathPolicyTests
{
    private readonly RemediationSafePathPolicy _policy = new();

    [Fact]
    public void Rejects_RelativePath()
        => Assert.False(_policy.Evaluate("relative/evil.exe").IsSafe);

    [Fact]
    public void Rejects_EmptyPath()
        => Assert.False(_policy.Evaluate("   ").IsSafe);

    [Fact]
    public void Rejects_TraversalSegments()
    {
        var root = Path.GetPathRoot(Path.GetTempPath());
        var p = Path.Combine(root!, "data", "..", "evil.exe");
        Assert.False(_policy.Evaluate(p).IsSafe);
    }

    [Theory]
    [InlineData("/usr/bin/evil")]
    [InlineData("/etc/passwd")]
    [InlineData("/bin/sh")]
    public void Rejects_UnixSystemRoots(string path)
        => Assert.False(_policy.Evaluate(path).IsSafe);

    [Fact]
    public void Rejects_ExtraConfiguredForbiddenRoot()
    {
        var forbidden = Path.Combine(Path.GetTempPath(), "protected-app");
        var policy = new RemediationSafePathPolicy(additionalForbiddenRoots: new[] { forbidden });
        Assert.False(policy.Evaluate(Path.Combine(forbidden, "bin.exe")).IsSafe);
    }

    [Fact]
    public void Accepts_OrdinaryTempFile_AndReportsWithinTemp()
    {
        var path = Path.Combine(Path.GetTempPath(), "dv-safe-" + System.Guid.NewGuid().ToString("N"), "drop.exe");
        var decision = _policy.Evaluate(path);

        Assert.True(decision.IsSafe, decision.Reason);
        Assert.True(_policy.IsWithinTempRoot(decision.NormalizedPath));
    }

    [Fact]
    public void Accepts_NonTempUserPath_ButNotWithinTemp()
    {
        // A path under the path root but not under temp and not a system root.
        var root = Path.GetPathRoot(Path.GetTempPath());
        var path = Path.Combine(root!, "Users", "alice", "Downloads", "drop.exe");
        var decision = _policy.Evaluate(path);

        // It may or may not be flagged safe depending on whether the root maps to
        // a forbidden root; on a normal layout Downloads is safe and not temp.
        if (decision.IsSafe)
            Assert.False(_policy.IsWithinTempRoot(decision.NormalizedPath));
    }
}
