// AMSI ingest wire protocol — native encoder.
//
// This MUST stay byte-for-byte compatible with the managed decoder in
// DataVanger.Infrastructure/Runtime/Amsi/AmsiIngestProtocol.cs. The layout is
// deliberately trivial so this shim can emit it with a single fixed stack
// buffer and zero parsing libraries — nothing here allocates on the heap.
//
// Layout (little-endian):
//   offset  0 : magic          u8[4] = { 'D','V','A','1' }
//   offset  4 : pid            u32
//   offset  8 : session        u64
//   offset 16 : appNameLen     u16   (<= kMaxNameBytes)
//   offset 18 : contentNameLen u16   (<= kMaxNameBytes)
//   offset 20 : contentLen     u32   (<= kMaxContentBytes)
//   offset 24 : appName        u8[appNameLen]        (UTF-8)
//             : contentName    u8[contentNameLen]    (UTF-8)
//             : content        u8[contentLen]        (UTF-8 prefix)

#pragma once

#include <cstdint>
#include <cstring>

namespace dv {

constexpr uint32_t kHeaderBytes = 24;
constexpr uint32_t kMaxNameBytes = 256;
constexpr uint32_t kMaxContentBytes = 16 * 1024; // matches RuntimeTelemetryEvent.MaxScriptContentLength
constexpr uint32_t kMaxFrameBytes = kHeaderBytes + (2 * kMaxNameBytes) + kMaxContentBytes;

// Writes little-endian integers regardless of host endianness (x86/x64 are LE,
// but this stays explicit so the format never depends on the compiler).
inline void PutU16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

inline void PutU32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

inline void PutU64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

// Truncate a UTF-8 byte length to a cap without splitting a multi-byte sequence.
inline uint32_t ClampUtf8Length(const uint8_t* data, uint32_t len, uint32_t cap) {
    if (len <= cap) return len;
    uint32_t end = cap;
    while (end > 0 && (data[end] & 0xC0) == 0x80) --end; // back off continuation bytes
    return end;
}

// Builds a frame into `out` (capacity `outCap`). Returns the total frame length,
// or 0 if the buffer is too small. All inputs are treated as UTF-8 bytes and
// clamped to their caps, so the output is always a valid frame.
inline uint32_t BuildFrame(uint8_t* out, uint32_t outCap,
                           const uint8_t* appName, uint32_t appLen,
                           const uint8_t* contentName, uint32_t nameLen,
                           uint32_t pid, uint64_t session,
                           const uint8_t* content, uint32_t contentLen) {
    appLen = ClampUtf8Length(appName, appLen, kMaxNameBytes);
    nameLen = ClampUtf8Length(contentName, nameLen, kMaxNameBytes);
    contentLen = ClampUtf8Length(content, contentLen, kMaxContentBytes);

    const uint32_t total = kHeaderBytes + appLen + nameLen + contentLen;
    if (total > outCap || total > kMaxFrameBytes) return 0;

    out[0] = 'D'; out[1] = 'V'; out[2] = 'A'; out[3] = '1';
    PutU32(out + 4, pid);
    PutU64(out + 8, session);
    PutU16(out + 16, static_cast<uint16_t>(appLen));
    PutU16(out + 18, static_cast<uint16_t>(nameLen));
    PutU32(out + 20, contentLen);

    uint32_t offset = kHeaderBytes;
    if (appLen)     { std::memcpy(out + offset, appName, appLen);         offset += appLen; }
    if (nameLen)    { std::memcpy(out + offset, contentName, nameLen);    offset += nameLen; }
    if (contentLen) { std::memcpy(out + offset, content, contentLen); }

    return total;
}

} // namespace dv
