#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace unknown::native {

/**
 * Dense interning of permission strings backed by an open-addressing table.
 *
 * Rule compilation interns every permission mentioned by any
 * PermissionComboRule; evaluation then maps each requested permission to a
 * dense id with a single allocation-free probe, so permission combinations
 * are checked with a couple of bitmap word operations.
 */
class PermissionIndex final {
public:
    /** Registers [name] (copied into owned storage) and returns its dense id. */
    std::uint32_t intern(std::string_view name);

    /** Dense id of [name] or -1 when it was never interned. Allocation-free. */
    [[nodiscard]] std::int32_t find(std::string_view name) const noexcept;

    [[nodiscard]] std::uint32_t size() const noexcept { return count_; }

    /** Grows the table ahead of bulk interning. */
    void reserve(std::size_t expected);

private:
    void rehash();

    struct Slot {
        std::uint64_t hash;
        std::int32_t id;
    };

    std::vector<Slot> table_;  // power-of-two sized; id == -1 marks an empty slot
    std::vector<std::string> owned_;
    std::uint32_t count_ = 0;
    std::uint64_t mask_ = 0;
};

/**
 * Curated table of Android dangerous / special permissions, used by the
 * TargetSdkRule evasion heuristic. Lookup is an allocation-free binary
 * search over a sorted static array.
 */
[[nodiscard]] bool isDangerousPermission(std::string_view permission) noexcept;

}  // namespace unknown::native
