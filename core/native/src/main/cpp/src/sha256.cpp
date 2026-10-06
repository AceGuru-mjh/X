#include "unknown_native/sha256.h"

#include <cstring>

namespace unknown::native {

namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline std::uint32_t rotr(std::uint32_t value, int bits) noexcept {
    return (value >> bits) | (value << (32 - bits));
}

}  // namespace

void Sha256::reset() noexcept {
    state_[0] = 0x6a09e667;
    state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372;
    state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f;
    state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab;
    state_[7] = 0x5be0cd19;
    totalBytes_ = 0;
    bufferFill_ = 0;
}

void Sha256::update(const void* data, std::size_t length) noexcept {
    if (length == 0) {
        return;
    }
    const std::uint8_t* cursor = static_cast<const std::uint8_t*>(data);
    totalBytes_ += length;

    if (bufferFill_ > 0) {
        const std::size_t need = 64 - bufferFill_;
        const std::size_t take = (length < need) ? length : need;
        std::memcpy(buffer_ + bufferFill_, cursor, take);
        bufferFill_ += take;
        cursor += take;
        length -= take;
        if (bufferFill_ == 64) {
            processBlock(buffer_);
            bufferFill_ = 0;
        }
    }
    while (length >= 64) {
        processBlock(cursor);
        cursor += 64;
        length -= 64;
    }
    if (length > 0) {
        std::memcpy(buffer_, cursor, length);
        bufferFill_ = length;
    }
}

void Sha256::finish(std::uint8_t out[32]) noexcept {
    const std::uint64_t bitLength = totalBytes_ * 8;

    buffer_[bufferFill_++] = 0x80;
    if (bufferFill_ > 56) {
        std::memset(buffer_ + bufferFill_, 0, 64 - bufferFill_);
        processBlock(buffer_);
        bufferFill_ = 0;
    }
    std::memset(buffer_ + bufferFill_, 0, 56 - bufferFill_);
    for (int i = 0; i < 8; ++i) {
        buffer_[56 + i] = static_cast<std::uint8_t>(bitLength >> (56 - 8 * i));
    }
    processBlock(buffer_);

    for (int i = 0; i < 8; ++i) {
        out[4 * i] = static_cast<std::uint8_t>(state_[i] >> 24);
        out[4 * i + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
        out[4 * i + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
        out[4 * i + 3] = static_cast<std::uint8_t>(state_[i]);
    }
    reset();
}

void Sha256::processBlock(const std::uint8_t* block) noexcept {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[4 * i]) << 24) |
               (static_cast<std::uint32_t>(block[4 * i + 1]) << 16) |
               (static_cast<std::uint32_t>(block[4 * i + 2]) << 8) |
               static_cast<std::uint32_t>(block[4 * i + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (int i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t temp1 = h + s1 + ch + kRoundConstants[i] + w[i];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

std::string toHexLower(const std::uint8_t* data, std::size_t length) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        out[2 * i] = kDigits[data[i] >> 4];
        out[2 * i + 1] = kDigits[data[i] & 0x0f];
    }
    return out;
}

bool isValidSha256Hex(std::string_view hex) noexcept {
    if (hex.size() != 64) {
        return false;
    }
    for (const char c : hex) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool normalizeSha256Hex(std::string_view hex, char* out64) noexcept {
    if (!isValidSha256Hex(hex)) {
        return false;
    }
    for (std::size_t i = 0; i < 64; ++i) {
        char c = hex[i];
        if (c >= 'A' && c <= 'F') {
            c = static_cast<char>(c - 'A' + 'a');
        }
        out64[i] = c;
    }
    return true;
}

}  // namespace unknown::native
