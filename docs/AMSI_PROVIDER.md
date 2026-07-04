# Real AMSI Provider (`IAntimalwareProvider`) — design, build, and manual validation

DataVanger can register a **real AMSI provider**: a native DLL that Windows'
`amsi.dll` loads **in-process** inside every program that calls AMSI (PowerShell,
`wscript`/`cscript`, Office, any custom AMSI host). The provider **only
observes** — it forwards a bounded content prefix to the DataVanger service and
**always returns `AMSI_RESULT_CLEAN`**. It never blocks, never quarantines, and
never returns a verdict.

This is **opt-in** and **admin-gated** on both sides (registering the provider,
and enabling the service ingest). Nothing here starts automatically.

---

## Why a native shim + IPC (not a managed COM provider)

An AMSI provider is loaded into **third-party** processes. Loading the .NET CLR
into arbitrary host processes (PowerShell, Office, …) is invasive and risky, and
it conflicts with the hard requirement that a fault in our code can never
destabilize the host. So the provider is a **minimal native C++ shim** with no
heavy dependencies, and the actual analysis happens back in the DataVanger
service, reached over a **write-only named pipe**.

```
PowerShell / wscript / Office  (third-party process, any local user)
   └─ amsi.dll → loads DataVanger.AmsiProvider.dll  (native, IAntimalwareProvider)
        └─ Scan():
             • copies ≤ 16 KB content prefix into a fixed stack buffer
             • fire-and-forgets one frame over the INGEST named pipe
             • ALWAYS sets AMSI_RESULT_CLEAN and returns S_OK
             • SEH-wrapped: any internal fault is swallowed (host never sees it)
                        │
                        ▼  \\.\pipe\DataVanger.Service.AmsiIngest  (write-only)
DataVanger.Service  (SYSTEM, admin, opt-in)
   └─ PipeIngestAmsiProvider  (ingest listener)
        • validates every frame (strict framing, size caps, rate limit)
        • runs AmsiContentAnalyzer / AmsiBypassDetector
        • raises EventReceived → AmsiRuntimeBridge (unchanged)
                        ▼
   RuntimeSecurityEvent(Category = ScriptObserved)  →  behavioral pipeline
        (evidence-only; NEVER confirms malware; NEVER triggers quarantine/block)
```

## Security model (the non-negotiables)

- **Fail-open, always.** `Scan()` reports `AMSI_RESULT_CLEAN` and returns `S_OK`
  before doing anything else, and the observation path is wrapped in SEH
  (`__try/__except`). A crash, hang, or any error in the provider can never
  block content or destabilize the host program.
- **Bounded, non-blocking.** The shim copies at most **16 KB** of the scanned
  buffer into a fixed stack frame and writes it with a short pipe-connect
  timeout. If the service pipe is absent or busy, the frame is dropped. No heap
  allocation on the hot path, no unbounded I/O.
- **Observe only.** The service raises evidence-only `ScriptObserved` telemetry.
  Per `ThreatClassificationPolicy`, AMSI/runtime events **never confirm malware
  on their own** and **never authorize automatic quarantine**. Active blocking
  is intentionally out of scope (see "Blocking" below).
- **Least-privilege ingest ACL.** The ingest pipe grants **Authenticated Users
  connect + write only** (they run the provider inside their own processes) —
  never read (a caller can't read another process's telemetry) and never
  `CreateNewInstance` (a caller can't stand up a rogue server to squat the
  name). Network logons are denied. The **control** pipe stays Admin/SYSTEM-only.
- **Opt-in + admin-gated.** Registration writes under `HKLM` and requires an
  elevated prompt (no silent elevation). Enabling the service ingest is a
  separate, default-off config flag.

## Components

| Layer | Path | Built in CI? |
| --- | --- | --- |
| Native provider shim | `native/DataVanger.AmsiProvider/` | ❌ manual (MSVC) |
| Ingest wire protocol (managed) | `DataVanger.Infrastructure/Runtime/Amsi/AmsiIngestProtocol.cs` | ✅ |
| Ingest wire protocol (native mirror) | `native/DataVanger.AmsiProvider/AmsiIngestProtocol.h` | ❌ manual |
| Ingest listener | `DataVanger.Infrastructure/Runtime/Amsi/PipeIngestAmsiProvider.cs` | ✅ |
| Ingest pipe ACL | `DataVanger.Infrastructure/Ipc/IpcPipeSecurity.cs` (`BuildIngestAcl`) | ✅ |
| Provider selection seam | `AmsiProviderFactory.Create(AmsiProviderMode.RealProvider)` | ✅ |
| COM registration plan | `DataVanger.Service/Hosting/AmsiProviderRegistration.cs` | ✅ |
| Service wiring / opt-in gate | `DataVangerServiceRuntime` + `EnableRealAmsiProvider` | ✅ |

> The managed side is fully covered by CI tests
> (`DataVanger.Tests/AmsiRealProviderTests.cs`): protocol round-trip + fail-open
> decode, ingest fail-open/rate-limit, anti-block (AMSI stays `ScriptObserved`
> and never reaches quarantine), single-provider coexistence, registration-plan
> correctness + admin gating, and the ingest ACL. Only the native shim requires
> the manual drill below.

## Provider CLSID

```
{6D6D9F2E-3A7C-4C1E-9B3A-2F5D8E1A4C90}
```

This value is shared by three places and must stay in sync:
`AmsiProviderRegistration.ProviderClsid` (C#), `CLSID_DataVangerAmsiProvider`
(C++), and the registry entries.

---

## Build the native shim (Windows, MSVC)

Requires Visual Studio (Desktop C++ workload) or the Build Tools with the
Windows SDK (for `amsi.h` / `amsi.lib`).

```powershell
cmake -S native/DataVanger.AmsiProvider -B build/amsi -A x64
cmake --build build/amsi --config Release
# → build/amsi/Release/DataVanger.AmsiProvider.dll  (64-bit)
```

For **32-bit** AMSI hosts (many Office installs, older scripting hosts), also
build the Win32 configuration and register that DLL in the 32-bit COM view:

```powershell
cmake -S native/DataVanger.AmsiProvider -B build/amsi32 -A Win32
cmake --build build/amsi32 --config Release
```

## Register the provider (elevated)

Two equivalent options — both are explicit and admin-gated. Use the CLI form
for the 64-bit view; use `regsvr32` per-DLL when you need to control bitness.

**Option A — DataVanger CLI (registers the 64-bit COM view):**

```powershell
DataVanger.Service.exe --register-amsi-provider --provider-dll "C:\path\to\DataVanger.AmsiProvider.dll"
```

**Option B — regsvr32 (per-DLL, picks the view by bitness):**

```powershell
regsvr32 "C:\path\to\DataVanger.AmsiProvider.dll"          # 64-bit
regsvr32 "C:\path\to\x86\DataVanger.AmsiProvider.dll"      # 32-bit hosts
```

Both write:

```
HKLM\SOFTWARE\Classes\CLSID\{CLSID}\                       (default) = "DataVanger AMSI Provider"
HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32\        (default) = <dll path>
                                                            ThreadingModel = Both
HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}\            (default) = "DataVanger AMSI Provider"
```

## Enable the service ingest (default OFF)

The service only hosts the ingest listener when the opt-in gate is set **and**
it runs as a genuine Windows service. In the service config JSON:

```json
{ "EnableRealAmsiProvider": true }
```

Install the service pointing at that config (existing flow):

```powershell
DataVanger.Service.exe --install --config "C:\ProgramData\DataVanger\service.json"
```

When enabled, the real ingest provider **replaces** the in-memory provider — a
single provider is hosted, so events are never duplicated. If the listener can't
be hosted (non-Windows, name already in use), the service degrades to the
in-memory provider and logs a warning; it never crashes.

## Manual end-to-end validation (Windows x64 + admin)

1. Build + register the provider; install/start the service with
   `EnableRealAmsiProvider: true`.
2. Open a **new** PowerShell window (AMSI providers are picked up per new host).
3. Run content that trips the analyzer, e.g. a classic AMSI-bypass string or an
   encoded command. PowerShell keeps working normally — nothing is blocked.
4. Confirm the service observed it: a `ScriptObserved` runtime event / behavioral
   evidence item appears (via the status snapshot / telemetry). Verify it is
   evidence-only (`IsConfirmedMalware = false`) and that **no** quarantine or
   block action was taken.
5. **Fail-open proof:** stop the DataVanger service, then run more scripts in
   PowerShell. Everything still runs with no added latency or errors — with no
   listener, the shim simply drops frames and returns clean.

## Uninstall

```powershell
DataVanger.Service.exe --unregister-amsi-provider     # or: regsvr32 /u <dll>
DataVanger.Service.exe --uninstall
```

Then close any host processes that already loaded the provider (a running
PowerShell keeps the DLL until it exits).

---

## Blocking is out of scope (deliberately)

An AMSI provider *can* return `AMSI_RESULT_DETECTED` to block content. DataVanger
**does not**, and this shim always returns clean. Active in-process blocking is a
much higher-risk capability (it can break legitimate software, and a provider
fault then becomes a host-visible failure). If a future case justifies blocking,
it should be proposed as a **separate** design with its own review — not folded
into this observe-only path.

## Risks / notes

- **CI does not build the native shim** (no MSVC toolchain, and an AMSI provider
  can't be exercised from CI). It is manual by design; the managed contract it
  depends on is fully tested.
- **Pipe-name squatting:** the first creator of the pipe name owns it. A hostile
  local process could pre-create it to *drop* telemetry (a DoS of visibility) —
  but never to harm a host (the shim fire-and-forgets and always returns clean),
  and the service surfaces a warning when it can't bind the name.
- **Bitness:** a 64-bit provider is only loaded into 64-bit hosts (and vice
  versa). Register both DLLs if you need coverage of 32-bit hosts.

## Wire protocol (frame layout)

Little-endian; one frame per pipe connection. The managed decoder rejects any
frame that fails these checks (wrong magic, truncation, an over-cap length, or a
total-size mismatch) with no event and no throw.

```
offset  0 : magic          u8[4]  = { 'D','V','A','1' }
offset  4 : pid            u32
offset  8 : session        u64
offset 16 : appNameLen     u16    (<= 256)
offset 18 : contentNameLen u16    (<= 256)
offset 20 : contentLen     u32    (<= 16384)
offset 24 : appName        u8[appNameLen]        (UTF-8)
          : contentName    u8[contentNameLen]    (UTF-8)
          : content        u8[contentLen]        (UTF-8 prefix)
```

Reference encoders: `AmsiIngestProtocol.Encode` (C#) and `dv::BuildFrame`
(`AmsiIngestProtocol.h`, C++). They must stay byte-for-byte identical.
