#pragma once

#include <cstdint>
#include <string_view>

namespace unknown::native::detail {

/** FNV-1a 64-bit over raw bytes. */
inline std::uint64_t fnv1a64(std::string_view text) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char c : text) {
        hash ^= static_cast<std::uint8_t>(c);
        hash *= 1099511628211ULL;
    }
    return hash;
}

}  // namespace unknown::native::detail
