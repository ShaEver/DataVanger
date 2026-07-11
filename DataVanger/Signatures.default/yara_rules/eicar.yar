/*
  DataVanger — starter YARA pack (FP-safe baseline).

  This file ships a single, unambiguous rule for the EICAR Standard Anti-Virus
  Test File — the industry-standard harmless test artifact (https://www.eicar.org).
  It exists so the YARA engine loads at least one rule out of the box
  (YaraRulesLoaded > 0) and the scan/match path is exercised end-to-end without
  distributing any real malware.

  The matched token is the distinctive EICAR marker substring (no backslash), so
  it matches identically under the real libyara backend and the lightweight
  fallback. DataVanger excludes its own signature data from scanning, so this rule
  never self-matches its own file.

  Add real detection rules via the signed update feed (UpdatePackageKind.YaraRules)
  or by dropping .yar/.yara files into <SignatureRoot>\yara_rules.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR Standard Anti-Virus Test File (harmless industry test artifact)"
        reference   = "https://www.eicar.org"
        author      = "DataVanger starter pack"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $eicar
}
