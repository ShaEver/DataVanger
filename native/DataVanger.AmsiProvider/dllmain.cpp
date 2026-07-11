// DataVanger AMSI Provider — native shim (IAntimalwareProvider).
//
// amsi.dll loads this DLL IN-PROCESS inside every third-party program that
// calls AMSI (PowerShell, wscript/cscript, Office, custom AMSI hosts). Because
// it runs inside software we do not own, its ONE hard rule is: never disturb the
// host.
//
//   * FAIL-OPEN, ALWAYS. Scan() always reports AMSI_RESULT_CLEAN and returns
//     S_OK, even on any internal error. It is wrapped in SEH so a structured
//     exception can never propagate into the host. It NEVER blocks content.
//   * BOUNDED, NON-BLOCKING. It copies at most kMaxContentBytes of the scanned
//     buffer into a fixed stack frame and fire-and-forgets it over a named pipe
//     with a short connect timeout. If the service pipe is absent or busy, the
//     frame is dropped. No heap allocation on the hot path, no unbounded I/O.
//   * OBSERVE ONLY. The service on the other end of the pipe only raises
//     evidence-only telemetry; nothing here (or there) blocks, quarantines, or
//     decides. Active blocking is intentionally out of scope.
//
// This file is NOT built in CI (no MSVC/C++ toolchain there and it cannot be
// loaded into third-party processes in CI). Build + registration + manual
// validation steps are in docs/AMSI_PROVIDER.md.

#include <windows.h>
#include <amsi.h>
#include <objbase.h>
#include <cstdint>

#include "AmsiIngestProtocol.h"

// {6D6D9F2E-3A7C-4C1E-9B3A-2F5D8E1A4C90}
// MUST match AmsiProviderRegistration.ProviderClsid and the registry entries.
static const CLSID CLSID_DataVangerAmsiProvider = {
    0x6d6d9f2e, 0x3a7c, 0x4c1e, {0x9b, 0x3a, 0x2f, 0x5d, 0x8e, 0x1a, 0x4c, 0x90}};

static const wchar_t* kProviderDisplayName = L"DataVanger AMSI Provider";
static const wchar_t* kIngestPipeName = L"\\\\.\\pipe\\DataVanger.Service.AmsiIngest";
static const DWORD kPipeBusyWaitMs = 50;

static LONG g_dllRefs = 0;
static HMODULE g_module = nullptr;

// ── Fire-and-forget send (bounded, never blocks the host meaningfully) ───────

static void SendFrame(const uint8_t* frame, DWORD len) {
    HANDLE h = CreateFileW(kIngestPipeName, GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(kIngestPipeName, kPipeBusyWaitMs)) {
            h = CreateFileW(kIngestPipeName, GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, 0, nullptr);
        }
        if (h == INVALID_HANDLE_VALUE) {
            return; // no service listening / still busy → drop, fail open
        }
    }
    DWORD written = 0;
    WriteFile(h, frame, len, &written, nullptr);
    CloseHandle(h);
}

// Copy an AMSI wide-string attribute into a UTF-8 buffer. Returns UTF-8 length.
static uint32_t ReadWideAttrUtf8(IAmsiStream* stream, AMSI_ATTRIBUTE attr,
                                 uint8_t* out, uint32_t outCap) {
    // wide buffer to receive the LPWSTR attribute (bytes, NUL-terminated)
    wchar_t wide[512];
    ULONG retBytes = 0;
    HRESULT hr = stream->GetAttribute(attr, sizeof(wide), reinterpret_cast<unsigned char*>(wide), &retBytes);
    if (FAILED(hr) || retBytes < sizeof(wchar_t)) return 0;

    int wchars = static_cast<int>(retBytes / sizeof(wchar_t));
    if (wchars > 0 && wide[wchars - 1] == L'\0') --wchars; // drop trailing NUL
    if (wchars <= 0) return 0;

    int n = WideCharToMultiByte(CP_UTF8, 0, wide, wchars,
                                reinterpret_cast<char*>(out), static_cast<int>(outCap),
                                nullptr, nullptr);
    return n > 0 ? static_cast<uint32_t>(n) : 0;
}

// The bounded, allocation-free body. Uses only POD/stack buffers and Win32
// calls (no C++ objects requiring unwinding), so it is safe under SEH.
static void TryForward(IAmsiStream* stream) {
    // Content pointer + size (the buffer AMSI is scanning).
    ULONGLONG contentSize = 0;
    unsigned char* contentAddr = nullptr;
    ULONG ret = 0;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(contentSize),
                         reinterpret_cast<unsigned char*>(&contentSize), &ret);
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(contentAddr),
                         reinterpret_cast<unsigned char*>(&contentAddr), &ret);
    if (contentAddr == nullptr || contentSize == 0) return;

    uint32_t copyLen = (contentSize > dv::kMaxContentBytes)
                           ? dv::kMaxContentBytes
                           : static_cast<uint32_t>(contentSize);

    uint8_t appName[dv::kMaxNameBytes];
    uint8_t contentName[dv::kMaxNameBytes];
    uint32_t appLen = ReadWideAttrUtf8(stream, AMSI_ATTRIBUTE_APP_NAME, appName, sizeof(appName));
    uint32_t nameLen = ReadWideAttrUtf8(stream, AMSI_ATTRIBUTE_CONTENT_NAME, contentName, sizeof(contentName));

    ULONGLONG session = 0;
    stream->GetAttribute(AMSI_ATTRIBUTE_SESSION, sizeof(session),
                         reinterpret_cast<unsigned char*>(&session), &ret);

    // Build the frame in a single fixed stack buffer — no heap on the hot path.
    static thread_local uint8_t frame[dv::kMaxFrameBytes];
    uint32_t frameLen = dv::BuildFrame(
        frame, sizeof(frame),
        appName, appLen,
        contentName, nameLen,
        GetCurrentProcessId(), session,
        contentAddr, copyLen);
    if (frameLen == 0) return;

    SendFrame(frame, frameLen);
}

// ── IAntimalwareProvider implementation ──────────────────────────────────────

class DataVangerAmsiProvider : public IAntimalwareProvider {
public:
    DataVangerAmsiProvider() : refs_(1) { InterlockedIncrement(&g_dllRefs); }
    virtual ~DataVangerAmsiProvider() { InterlockedDecrement(&g_dllRefs); }

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider)) {
            *ppv = static_cast<IAntimalwareProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&refs_);
        if (r == 0) delete this;
        return r;
    }

    // IAntimalwareProvider
    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override {
        // FAIL-OPEN: report clean up front, then best-effort observe. Nothing
        // below can change the verdict or block the host.
        if (result) *result = AMSI_RESULT_CLEAN;
        __try {
            if (stream) TryForward(stream);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Swallow: a fault in our observation path must never reach the host.
        }
        return S_OK;
    }

    void STDMETHODCALLTYPE CloseSession(ULONGLONG /*session*/) override {
        // Stateless: we hold nothing per session.
    }

    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) override {
        if (!displayName) return E_POINTER;
        const size_t bytes = (wcslen(kProviderDisplayName) + 1) * sizeof(wchar_t);
        auto* buf = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (!buf) return E_OUTOFMEMORY;
        memcpy(buf, kProviderDisplayName, bytes);
        *displayName = buf;
        return S_OK;
    }

private:
    LONG refs_;
};

// ── Class factory ────────────────────────────────────────────────────────────

class ProviderClassFactory : public IClassFactory {
public:
    ProviderClassFactory() : refs_(1) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&refs_);
        if (r == 0) delete this;
        return r;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* provider = new (std::nothrow) DataVangerAmsiProvider();
        if (!provider) return E_OUTOFMEMORY;
        HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_dllRefs);
        else InterlockedDecrement(&g_dllRefs);
        return S_OK;
    }

private:
    LONG refs_;
};

// ── Registration helpers (so regsvr32 works as an alternative to the CLI) ─────

static LONG SetKeyString(HKEY root, const wchar_t* subKey, const wchar_t* valueName,
                         const wchar_t* value) {
    HKEY key = nullptr;
    LONG rc = RegCreateKeyExW(root, subKey, 0, nullptr, 0,
                              KEY_WRITE | KEY_WOW64_64KEY, nullptr, &key, nullptr);
    if (rc != ERROR_SUCCESS) return rc;
    rc = RegSetValueExW(key, valueName, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(value),
                        static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return rc;
}

static void ClsidKeyPaths(wchar_t* clsidKey, size_t clsidCap,
                          wchar_t* inprocKey, size_t inprocCap,
                          wchar_t* amsiKey, size_t amsiCap) {
    wchar_t clsid[64];
    StringFromGUID2(CLSID_DataVangerAmsiProvider, clsid, 64);
    swprintf_s(clsidKey, clsidCap, L"SOFTWARE\\Classes\\CLSID\\%s", clsid);
    swprintf_s(inprocKey, inprocCap, L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    swprintf_s(amsiKey, amsiCap, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", clsid);
}

// ── DLL exports ──────────────────────────────────────────────────────────────

extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (rclsid != CLSID_DataVangerAmsiProvider) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new (std::nothrow) ProviderClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

extern "C" HRESULT __stdcall DllCanUnloadNow() {
    return (InterlockedCompareExchange(&g_dllRefs, 0, 0) == 0) ? S_OK : S_FALSE;
}

extern "C" HRESULT __stdcall DllRegisterServer() {
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(g_module, modulePath, MAX_PATH) == 0) return E_FAIL;

    wchar_t clsidKey[128], inprocKey[160], amsiKey[160];
    ClsidKeyPaths(clsidKey, 128, inprocKey, 160, amsiKey, 160);

    if (SetKeyString(HKEY_LOCAL_MACHINE, clsidKey, nullptr, kProviderDisplayName) != ERROR_SUCCESS) return E_ACCESSDENIED;
    if (SetKeyString(HKEY_LOCAL_MACHINE, inprocKey, nullptr, modulePath) != ERROR_SUCCESS) return E_ACCESSDENIED;
    if (SetKeyString(HKEY_LOCAL_MACHINE, inprocKey, L"ThreadingModel", L"Both") != ERROR_SUCCESS) return E_ACCESSDENIED;
    if (SetKeyString(HKEY_LOCAL_MACHINE, amsiKey, nullptr, kProviderDisplayName) != ERROR_SUCCESS) return E_ACCESSDENIED;
    return S_OK;
}

extern "C" HRESULT __stdcall DllUnregisterServer() {
    wchar_t clsidKey[128], inprocKey[160], amsiKey[160];
    ClsidKeyPaths(clsidKey, 128, inprocKey, 160, amsiKey, 160);

    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, amsiKey, KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, inprocKey, KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, clsidKey, KEY_WOW64_64KEY, 0);
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
