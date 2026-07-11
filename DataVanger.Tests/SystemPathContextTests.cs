using DataVanger.Core;
using DataVanger.Detection;

// BETA 11B — system-path context classification + bounded relief.
// Classification is exercised through the windir-relative internal overload so the
// tests are deterministic on any host OS (the production overload resolves the real
// %WinDir%). Key invariants asserted: genuine System32/SysWOW64/WinSxS/servicing
// classify; Windows\Temp and look-alikes (C:\Temp\System32, Downloads\System32,
// wrong drive) do NOT; and relief is bounded (can attenuate noise, never grant
// immunity) and zero for non-system/user-writable paths.
// Filters: ~SystemPath, ~PathTaxonomy, ~AntiFalsePositive, ~Detection.
public class SystemPathContextTests
{
    private const string WinDir = @"c:\windows\";

    private static SystemPathKind Classify(string p) =>
        PathTaxonomy.ClassifySystemPath(p.ToLowerInvariant(), WinDir);

    [Xunit.Fact]
    public void GenuineSystem32_Classifies()
    {
        Xunit.Assert.Equal(SystemPathKind.System32, Classify(@"c:\windows\system32\kerberos.dll"));
    }

    [Xunit.Fact]
    public void GenuineSysWOW64_Classifies()
    {
        Xunit.Assert.Equal(SystemPathKind.SysWOW64, Classify(@"c:\windows\syswow64\tlscsp.dll"));
    }

    [Xunit.Fact]
    public void GenuineWinSxS_Classifies()
    {
        Xunit.Assert.Equal(SystemPathKind.WinSxS,
            Classify(@"c:\windows\winsxs\amd64_microsoft-windows-security-kerberos_31bf3856ad364e35_10.0.26100.8655_none\kerberos.dll"));
    }

    [Xunit.Fact]
    public void GenuineServicing_Classifies()
    {
        Xunit.Assert.Equal(SystemPathKind.Servicing, Classify(@"c:\windows\servicing\trustedinstaller.exe"));
    }

    [Xunit.Fact]
    public void OtherWindowsComponent_ClassifiesAsOtherProtected()
    {
        Xunit.Assert.Equal(SystemPathKind.OtherProtectedWindows, Classify(@"c:\windows\explorer.exe"));
    }

    [Xunit.Fact]
    public void WindowsTemp_IsNotSystem()
    {
        // Windows\Temp is user-writable; it must not receive protected-system context.
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"c:\windows\temp\dropper.dll"));
    }

    [Xunit.Fact]
    public void WorldWritableWindowsSubdirs_AreNotSystem()
    {
        // Classic non-admin-writable / UAC-bypass locations inside %WinDir% get no relief.
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"c:\windows\system32\tasks\evil.dll"));
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"c:\windows\system32\spool\drivers\color\evil.dll"));
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"c:\windows\tasks\evil.dll"));
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"c:\windows\tracing\evil.dll"));
    }

    [Xunit.Fact]
    public void LookalikeUnderTemp_IsRejected()
    {
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"c:\temp\system32\evil.dll"));
    }

    [Xunit.Fact]
    public void LookalikeUnderDownloads_IsRejected()
    {
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"c:\users\bob\downloads\system32\evil.dll"));
    }

    [Xunit.Fact]
    public void WrongDriveWinSxS_IsRejected()
    {
        Xunit.Assert.Equal(SystemPathKind.None, Classify(@"d:\data\winsxs\evil.dll"));
    }

    [Xunit.Fact]
    public void BlankOrEmptyWindir_IsNone()
    {
        Xunit.Assert.Equal(SystemPathKind.None, PathTaxonomy.ClassifySystemPath("", WinDir));
        Xunit.Assert.Equal(SystemPathKind.None, PathTaxonomy.ClassifySystemPath(@"c:\windows\system32\x.dll", ""));
    }

    [Xunit.Fact]
    public void Relief_IsBounded_AndNeverGrantsImmunity()
    {
        // Bounded (<= 4) so a strongly corroborated file stays above HighRisk (9):
        foreach (var kind in new[]
        {
            SystemPathKind.System32, SystemPathKind.SysWOW64, SystemPathKind.WinSxS,
            SystemPathKind.Servicing, SystemPathKind.OtherProtectedWindows,
        })
        {
            int relief = PathTaxonomy.SystemPathRelief(kind);
            Xunit.Assert.InRange(relief, 1, 4);
            Xunit.Assert.True(relief < RiskThresholds.High, "Relief must be smaller than the HighRisk threshold (no immunity).");
        }
    }

    [Xunit.Fact]
    public void Relief_IsZero_ForNonSystemPaths()
    {
        Xunit.Assert.Equal(0, PathTaxonomy.SystemPathRelief(SystemPathKind.None));
    }
}
