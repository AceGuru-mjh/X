#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "unknown_native/rule_types.h"

namespace unknown::native {

/** Package facts needed for evaluation — views into caller-owned storage. */
struct Snapshot {
    std::string_view packageName;
    std::string_view label;
    std::int32_t targetSdk = 0;
    std::vector<std::string_view> permissions;
    /** Empty when the APK digest is unknown. */
    std::string_view sha256Hex;
};

/**
 * Wire protocol between Kotlin and the native core (see docs/NATIVE_ENGINE.md
 * for the full specification):
 *
 *   - fields of one record are separated by \x1F (unit separator)
 *   - lists inside a field are separated by \x1E (record separator)
 *   - rules are separated by '\n'
 *
 * Parsing is zero-copy: every view produced by the parser points into the
 * caller-provided blob, which must outlive the parsed structures.
 */
namespace protocol {

/**
 * Parses one snapshot line:
 *
 *   packageName \x1F label \x1F targetSdk \x1F perms(\x1E) \x1F sha256Hex
 *
 * Returns false and fills [error] on malformed input.
 */
bool parseSnapshot(std::string_view line, Snapshot* out, std::string* error);

}  // namespace protocol

}  // namespace unknown::native
