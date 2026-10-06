#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace unknown::native {

/** FIPS 180-4 SHA-256 with a streaming interface. */
class Sha256 final {
public:
    Sha256() noexcept { reset(); }

    void reset() noexcept;

    void update(const void* data, std::size_t length) noexcept;

    /** Writes 32 digest bytes and resets the state for reuse. */
    void finish(std::uint8_t out[32]) noexcept;

private:
    void processBlock(const std::uint8_t* block) noexcept;

    std::uint32_t state_[8];
    std::uint64_t totalBytes_;
    std::uint8_t buffer_[64];
    std::size_t bufferFill_;
};

/** Lowercase hex representation; returns exactly 2 * length characters. */
[[nodiscard]] std::string toHexLower(const std::uint8_t* data, std::size_t length);

/** True when [hex] is exactly 64 characters of [0-9a-fA-F]. */
[[nodiscard]] bool isValidSha256Hex(std::string_view hex) noexcept;

/** Folds ASCII hex to lowercase into [out64] (64 chars, no NUL). */
[[nodiscard]] bool normalizeSha256Hex(std::string_view hex, char* out64) noexcept;

}  // namespace unknown::native
