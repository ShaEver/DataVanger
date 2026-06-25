# 00_REMAINING_PHASES_INDEX — DataVanger V.Alpha remaining phases

Entry checkpoint: **`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`**
Final target: **`DataVanger V.Alpha_STABLE`**
Branch: `claude/fervent-dirac-0ml0N`

> Environment note: this planning round had **no .NET SDK**; the solution effectively
> targets `net8.0-windows` (DataVanger, DataVanger.Service, DataVanger.Tests). **No
> phase can be marked validated without a Windows `dotnet build` + `dotnet test`.**
> The `..._STABLE` claim is unproven until that green run exists (see phase 22).

## Generated phase files
- `08_XUNIT_WARNING_CLEANUP.md`
- `09_TEST_SUITE_DECOMPOSITION.md`
- `10_APPSETTINGS_SCHEMA_VERSIONING.md`
- `11_PUBLISHER_IDENTITY_VALIDATION.md`
- `12_REAL_LIBYARA_ACTIVATION.md`
- `13_YARA_RULE_PACK_VALIDATION.md`
- `14_SIGNED_UPDATE_HTTP_TRANSPORT.md`
- `15_WINDOWS_SERVICE_INSTALLATION.md`
- `16_IPC_ACL_HARDENING.md`
- `17_ETW_AMSI_REAL_PROVIDER.md`
- `18_MODULE_STATUS_UI_CLARITY.md`
- `19_QUARANTINE_RESTORE_UX.md`
- `20_DOCS_OPERATOR_GUIDE.md`
- `21_ANALYZESINGLEFILE_DECOMPOSITION.md`
- `22_FINAL_STABILIZATION.md`

## Recommended implementation order
1. 08_XUNIT_WARNING_CLEANUP
2. 20_DOCS_OPERATOR_GUIDE
3. 10_APPSETTINGS_SCHEMA_VERSIONING
4. 21_ANALYZESINGLEFILE_DECOMPOSITION
5. 09_TEST_SUITE_DECOMPOSITION
6. 18_MODULE_STATUS_UI_CLARITY
7. 11_PUBLISHER_IDENTITY_VALIDATION
8. 13_YARA_RULE_PACK_VALIDATION
9. 19_QUARANTINE_RESTORE_UX
10. 12_REAL_LIBYARA_ACTIVATION
11. 14_SIGNED_UPDATE_HTTP_TRANSPORT
12. 16_IPC_ACL_HARDENING
13. 15_WINDOWS_SERVICE_INSTALLATION
14. 17_ETW_AMSI_REAL_PROVIDER
15. 22_FINAL_STABILIZATION

> Note: 21 benefits from 09's granular tests first; if strict safety is preferred over
> the listed order, run 09 before 21. The order above follows the requested sequence.

## Dependency graph
```
08 ─► 09 ─► 21
08 ─► (independent hygiene: 20, 10, 18)
10 ─► 11        (publisher config via schema)
10 ─► 13        (rule-pack limits via schema)
10 ─► 14        (update feed config via schema)
12 ─► 13(real)  (real-engine rule packs need 12)
16 ─► 15 ─► 17  (ACLs with/before service; ETW/AMSI need the service host)
20  (independent, offline)
ALL selected ─► 22_FINAL_STABILIZATION
```

## Risk classification
| Phase | Risk |
|---|---|
| 08 XUNIT_WARNING_CLEANUP | Low |
| 09 TEST_SUITE_DECOMPOSITION | Low–Medium |
| 10 APPSETTINGS_SCHEMA_VERSIONING | Low–Medium |
| 11 PUBLISHER_IDENTITY_VALIDATION | High |
| 12 REAL_LIBYARA_ACTIVATION | High |
| 13 YARA_RULE_PACK_VALIDATION | Medium |
| 14 SIGNED_UPDATE_HTTP_TRANSPORT | High |
| 15 WINDOWS_SERVICE_INSTALLATION | High |
| 16 IPC_ACL_HARDENING | Medium–High |
| 17 ETW_AMSI_REAL_PROVIDER | High |
| 18 MODULE_STATUS_UI_CLARITY | Low |
| 19 QUARANTINE_RESTORE_UX | Low–Medium |
| 20 DOCS_OPERATOR_GUIDE | Very Low |
| 21 ANALYZESINGLEFILE_DECOMPOSITION | Medium |
| 22 FINAL_STABILIZATION | Medium |

## Complexity classification
| Phase | Complexity |
|---|---|
| 08 | Low | 
| 09 | Medium (large mechanical) |
| 10 | Low–Medium |
| 11 | High |
| 12 | High (native interop) |
| 13 | Medium |
| 14 | High (network/supply-chain) |
| 15 | High (OS lifecycle) |
| 16 | Medium |
| 17 | High (privilege/perf) |
| 18 | Low–Medium |
| 19 | Low–Medium |
| 20 | Low |
| 21 | Medium |
| 22 | Medium (aggregation) |

## Windows validation requirements
- **Validation requires Windows for ALL phases** (suite targets `net8.0-windows`).
- **Authoring is offline-safe (edits without SDK):** 08, 09, 10, 20, and most of 21.
- **Requires Windows runtime behavior (not just compile):** 11 (X509 chain), 12 (native libyara), 14 (network), 15 (service), 16 (pipe ACLs), 17 (ETW/AMSI), 18/19 (WPF).

## Codex stabilization recommendations
| Phase | Codex |
|---|---|
| 08, 09, 10, 18, 19, 20 | Optional / not required |
| 21 | Recommended (review-only; anti-FP spine) |
| 11, 12, 14, 15, 16, 17 | **Recommended (stabilize the risky boundary)** |
| 22 | **Recommended (final sign-off)** |

Pattern: **Claude implements the structured change; Codex GPT-5.5 High hardens native / network / OS / security boundaries.**

## Approval-gated phases
- 11 PUBLISHER_IDENTITY_VALIDATION (to change default mode / enable revocation)
- 12 REAL_LIBYARA_ACTIVATION (adding the package / enabling `YARA_REAL`)
- 14 SIGNED_UPDATE_HTTP_TRANSPORT (enabling the transport / any feed)
- 15 WINDOWS_SERVICE_INSTALLATION (registering / auto-start)
- 16 IPC_ACL_HARDENING (deploying with a real privileged service)
- 17 ETW_AMSI_REAL_PROVIDER (activating real providers)
- 22 FINAL_STABILIZATION (final release/tag)

## Safe-for-Claude-only (no approval needed to implement)
08, 09, 10, 13 (lightweight/local part), 18, 19, 20, 21. (11/16 machinery may be authored off-by-default; *enabling* is approval-gated.)

## Suggested checkpoint names
| After phase | Checkpoint |
|---|---|
| 08 | `DataVanger V.Alpha_XUNIT_CLEAN_STABLE` |
| 20 | `DataVanger V.Alpha_DOCS_STABLE` |
| 10 | `DataVanger V.Alpha_SETTINGS_SCHEMA_STABLE` |
| 21 | `DataVanger V.Alpha_SCANENGINE_REFACTOR_STABLE` |
| 09 | `DataVanger V.Alpha_TESTS_DECOMPOSED_STABLE` |
| 18 | `DataVanger V.Alpha_MODULE_STATUS_STABLE` |
| 11 | `DataVanger V.Alpha_PUBLISHER_IDENTITY_STABLE` |
| 13 | `DataVanger V.Alpha_YARA_RULEPACK_STABLE` |
| 19 | `DataVanger V.Alpha_QUARANTINE_UX_STABLE` |
| 12 | `DataVanger V.Alpha_LIBYARA_ACTIVE_STABLE` |
| 14 | `DataVanger V.Alpha_SIGNED_UPDATE_HTTP_STABLE` |
| 16 | `DataVanger V.Alpha_IPC_ACL_STABLE` |
| 15 | `DataVanger V.Alpha_WINSERVICE_STABLE` |
| 17 | `DataVanger V.Alpha_ETW_AMSI_STABLE` |
| 22 | `DataVanger V.Alpha_STABLE` |

## Suggested ZIP names
| Phase | ZIP |
|---|---|
| 08 | `DataVanger V.Alpha_XUNIT_CLEANUP_CLAUDE.zip` |
| 20 | `DataVanger V.Alpha_DOCS_CLAUDE.zip` |
| 10 | `DataVanger V.Alpha_SETTINGS_SCHEMA_CLAUDE.zip` |
| 21 | `DataVanger V.Alpha_SCANENGINE_REFACTOR_CLAUDE.zip` |
| 09 | `DataVanger V.Alpha_TESTS_DECOMPOSED_CLAUDE.zip` |
| 18 | `DataVanger V.Alpha_MODULE_STATUS_CLAUDE.zip` |
| 11 | `DataVanger V.Alpha_PUBLISHER_IDENTITY_CLAUDE.zip` |
| 13 | `DataVanger V.Alpha_YARA_RULEPACK_CLAUDE.zip` |
| 19 | `DataVanger V.Alpha_QUARANTINE_UX_CLAUDE.zip` |
| 12 | `DataVanger V.Alpha_LIBYARA_ACTIVE_CLAUDE.zip` |
| 14 | `DataVanger V.Alpha_SIGNED_UPDATE_HTTP_CLAUDE.zip` |
| 16 | `DataVanger V.Alpha_IPC_ACL_CLAUDE.zip` |
| 15 | `DataVanger V.Alpha_WINSERVICE_CLAUDE.zip` |
| 17 | `DataVanger V.Alpha_ETW_AMSI_CLAUDE.zip` |
| 22 | `DataVanger V.Alpha_STABLE_CLAUDE.zip` |

## Suggested Master Implementation Order titles
- `08 — xUnit Async Hygiene (xUnit1031), gated on a Windows baseline build+test`
- `20 — Operator/Developer Docs + Active/Prepared/Stub Status Matrix`
- `10 — AppSettings Schema Versioning & Lossless Migration`
- `21 — AnalyzeSingleFileAsync Move-Only Decomposition (behavior-identical)`
- `09 — Faithful Decomposition of LegacyParityTests`
- `18 — Honest Module Status (Active/Prepared/Fallback/Disabled/Stub/Degraded)`
- `11 — Certificate-Aware Publisher Identity Validation (opt-in)`
- `13 — Local YARA Rule-Pack Validation (no downloads)`
- `19 — Quarantine Restore UX & Audit Visibility`
- `12 — Real libyara Activation (approval-gated, Windows-validated)`
- `14 — Signed-Update HTTP Transport (opt-in, verify-before-trust)`
- `16 — Named-Pipe IPC ACL Hardening`
- `15 — Windows Service Lifecycle (install/uninstall/recovery)`
- `17 — Real ETW/AMSI Providers (bounded, telemetry-only)`
- `22 — Final V.Alpha Stabilization & Release Readiness`

## Invariant checks (every phase must keep these green)
```powershell
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'catch\s*\{\s*\}'

Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'lock\s*\(qm\)'

Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  ForEach-Object { $c = Get-Content $_.FullName -Raw; if ($c -match "`r") { $_.FullName } }
```
Expected: zero anonymous catch blocks · zero `lock(qm)` · zero CRLF `.cs` files.

## Baseline validation commands (every phase)
```powershell
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
dotnet build DataVanger.Service/DataVanger.Service.csproj
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
dotnet build DataVanger.sln
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
```

## Cross-cutting do-not-do-yet (applies to all phases)
1. No dnYara package / `YARA_REAL` without a green Windows restore+build+rule test.
2. No HTTP update network I/O without opt-in + signature/anti-downgrade + Windows validation.
3. No real Windows Service install/auto-start without approval.
4. No IPC ACL loosening; no remote pipes.
5. No auto-quarantine beyond ConfirmedMalware.
6. Real-YARA/behavioral/ETW/AMSI/update telemetry must never confirm malware alone.
7. No assertion changes to make tests pass; decompose faithfully.
8. No publisher-trust weakening; trusted signature never overrides a malicious hash.
9. No cloud/remote integrations.
10. Do not claim `..._STABLE` until a Windows build+test is green.

## Architectural findings (from current-repo inspection)
- **6 projects.** UI `DataVanger` (net8.0-windows, no active PackageReferences) + libs `Engine`/`Infrastructure`/`Shared`/`Service` (net8.0) + `Tests` (net8.0-windows: xunit 2.9, runner 2.8, Test.Sdk 17, coverlet 6). `Infrastructure` actively references TraceEvent 3.1.21 + ProtectedData 8.0.0 (DPAPI).
- **Implemented + tested:** Quarantine V2 (AES-GCM/HMAC, DPAPI key, audit, integrity-verified restore, ConfirmedMalware-only auto), Scheduler (tick-driven), Realtime (conservative decision engine), signed-update **verification** (RSA-PSS/ECDsa, anti-downgrade), Memory + Behavioral engines, per-section PE entropy.
- **Prepared, not active:** real libyara (`Infrastructure/LibyaraEngine.cs` `#if YARA_REAL`, no package); ETW/AMSI adapters (`IsAvailable=false`) with a real `WindowsEtwRuntimeProvider` available.
- **Stubbed:** `HttpUpdateTransport` (throws `NotSupportedException`); `--service` (Program.cs ~line 149 diagnostic stub); IPC ACLs (none — only `IpcSecurityPolicy` payload validation).
- **Needs audit:** Memory/Behavioral engines exist + are tested but are **not** in the per-file `EngineComposition` module set (runtime/service path — likely intentional); `Detection/Placeholders/PlaceholderModules.cs` `[Obsolete]` seams still present; `03_CORRIGIR_CSV` CSV quoting not re-verified this round.
- **Invariants clean:** anonymous `catch{}` = 0, `lock(qm)` = 0, CRLF `.cs` = 0; `.gitattributes` enforces `eol=lf`. 4 *typed* empty catches (allowed).
- **Test debt:** `LegacyParityTests.cs` ≈7,721 lines / **1** `[Fact]` / 49 sections; **226** xUnit1031 blocking-async calls; dedicated tests only for anti-FP, publishers, YARA fallback.
- **Config debt:** `AppSettings` has **no** schema version; 28/29 properties surfaced in `SettingsWindow` (the curated `TrustedPublishers` base list is intentionally not UI-exposed).
- **Docs debt:** `README.md` is effectively empty.
