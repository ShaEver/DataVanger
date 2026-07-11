# yara_rules — starter pack (default)

This folder is seeded (without overwriting) into
`%UserProfile%\DataVanger\Signatures\yara_rules\` on first run by
`DefaultSignaturePack.SeedYaraRules`. `.yar` and `.yara` files are copied.

## What ships here

- `eicar.yar` — a single, unambiguous rule for the EICAR test file. It is
  FP-safe and exists so the YARA engine loads at least one rule out of the box
  and the match path is exercised. It is **not** a real malware ruleset.

## Adding real coverage (operator / feed)

DataVanger does **not** ship a production malware ruleset (that is sourced from a
maintained threat feed). Two supported paths:

1. **Signed update feed (recommended).** Publish a signed update manifest with a
   `UpdatePackageKind.YaraRules` package; `SignedUpdateService` verifies it (ECDSA
   manifest + per-package SHA-256) and `FileSystemSignatureUpdateSink` writes it to
   `yara_rules/feed__<id>.yar`, which `LightweightYaraDatabase.Load` / the real
   libyara backend pick up on the next scan.
2. **Manual drop.** Place vetted `.yar`/`.yara` files in
   `<SignatureRoot>\yara_rules`. Keep them high-precision — broad/substring-style
   rules cause false positives in the lightweight fallback.

## Safety notes

- DataVanger excludes its own signature data (`Signatures.default` and the user
  `Signatures` root) from scan targets, so rule files never self-match.
- External YARA matches are evidence-only and **never** confirm malware on their
  own (anti-false-positive invariant). Only a known-bad hash or a curated
  `confirmed` rule can reach ConfirmedMalware.
