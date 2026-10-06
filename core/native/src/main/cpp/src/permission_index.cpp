#include "unknown_native/permission_index.h"

#include <algorithm>

#include "hash_utils.h"

namespace unknown::native {

namespace {

/**
 * Curated Android dangerous / special permissions for the TargetSdkRule
 * evasion heuristic. Sorted for binary search; kept intentionally small
 * and readable.
 */
constexpr std::string_view kDangerousPermissions[] = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.USE_SIP",
    "android.permission.UWB_RANGING",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.WRITE_SETTINGS",
};

}  // namespace

bool isDangerousPermission(std::string_view permission) noexcept {
    const auto* begin = std::begin(kDangerousPermissions);
    const auto* end = std::end(kDangerousPermissions);
    const auto* found = std::lower_bound(
        begin, end, permission,
        [](std::string_view lhs, std::string_view rhs) { return lhs < rhs; });
    return found != end && *found == permission;
}

void PermissionIndex::reserve(std::size_t expected) {
    owned_.reserve(expected);
    std::size_t capacity = 16;
    while (capacity < (expected + 1) * 2) {
        capacity <<= 1;
    }
    if (capacity <= table_.size()) {
        return;  // already roomy enough
    }
    // Rebuild from scratch so entries interned earlier stay resolvable.
    table_.assign(capacity, Slot{0, -1});
    mask_ = capacity - 1;
    for (std::size_t id = 0; id < owned_.size(); ++id) {
        const std::uint64_t hash = detail::fnv1a64(owned_[id]);
        std::size_t slot = static_cast<std::size_t>(hash) & mask_;
        while (table_[slot].id != -1) {
            slot = (slot + 1) & mask_;
        }
        table_[slot] = Slot{hash, static_cast<std::int32_t>(id)};
    }
}

void PermissionIndex::rehash() {
    const std::size_t capacity = table_.empty() ? 16 : table_.size() * 2;
    table_.assign(capacity, Slot{0, -1});
    mask_ = capacity - 1;
    for (std::size_t id = 0; id < owned_.size(); ++id) {
        const std::uint64_t hash = detail::fnv1a64(owned_[id]);
        std::size_t slot = static_cast<std::size_t>(hash) & mask_;
        while (table_[slot].id != -1) {
            slot = (slot + 1) & mask_;
        }
        table_[slot] = Slot{hash, static_cast<std::int32_t>(id)};
    }
}

std::uint32_t PermissionIndex::intern(std::string_view name) {
    if (count_ * 2 >= table_.size()) {
        rehash();
    }
    const std::uint64_t hash = detail::fnv1a64(name);
    std::size_t slot = static_cast<std::size_t>(hash) & mask_;
    while (table_[slot].id != -1) {
        if (table_[slot].hash == hash && owned_[static_cast<std::size_t>(table_[slot].id)] == name) {
            return static_cast<std::uint32_t>(table_[slot].id);
        }
        slot = (slot + 1) & mask_;
    }
    table_[slot] = Slot{hash, static_cast<std::int32_t>(count_)};
    owned_.emplace_back(name);
    return count_++;
}

std::int32_t PermissionIndex::find(std::string_view name) const noexcept {
    if (table_.empty()) {
        return -1;
    }
    const std::uint64_t hash = detail::fnv1a64(name);
    std::size_t slot = static_cast<std::size_t>(hash) & mask_;
    while (table_[slot].id != -1) {
        if (table_[slot].hash == hash && owned_[static_cast<std::size_t>(table_[slot].id)] == name) {
            return table_[slot].id;
        }
        slot = (slot + 1) & mask_;
    }
    return -1;
}

}  // namespace unknown::native
