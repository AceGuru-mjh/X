#include "unknown_native/protocol.h"

#include "parse_utils.h"
#include "unknown_native/sha256.h"

namespace unknown::native::protocol {

namespace {

using detail::FieldScanner;
using detail::parseInt32;

}  // namespace

bool parseSnapshot(std::string_view line, Snapshot* out, std::string* error) {
    if (out == nullptr) {
        if (error != nullptr) {
            *error = "null snapshot output";
        }
        return false;
    }
    *out = Snapshot{};

    if (!line.empty() && line.back() == '\n') {
        line.remove_suffix(1);
    }
    if (!line.empty() && line.back() == '\r') {
        line.remove_suffix(1);
    }

    FieldScanner scanner(line);
    std::string_view packageName;
    std::string_view label;
    std::string_view targetSdkText;
    std::string_view permissionsText;
    std::string_view sha256Text;

    if (!scanner.next(&packageName) || !scanner.next(&label) || !scanner.next(&targetSdkText) ||
        !scanner.next(&permissionsText) || !scanner.next(&sha256Text)) {
        if (error != nullptr) {
            *error = "snapshot record needs 5 fields: packageName, label, targetSdk, permissions, sha256";
        }
        return false;
    }
    if (!scanner.exhausted()) {
        if (error != nullptr) {
            *error = "snapshot record has too many fields";
        }
        return false;
    }
    if (packageName.empty()) {
        if (error != nullptr) {
            *error = "snapshot packageName is empty";
        }
        return false;
    }

    std::int32_t targetSdk = 0;
    if (!parseInt32(targetSdkText, &targetSdk)) {
        if (error != nullptr) {
            *error = "snapshot targetSdk is not an integer";
        }
        return false;
    }

    if (!sha256Text.empty() && !isValidSha256Hex(sha256Text)) {
        if (error != nullptr) {
            *error = "snapshot sha256 must be 64 hex characters";
        }
        return false;
    }

    out->packageName = packageName;
    out->label = label;
    out->targetSdk = targetSdk;
    out->sha256Hex = sha256Text;

    // Permissions: \x1E-separated list, possibly empty.
    if (!permissionsText.empty()) {
        std::string_view rest = permissionsText;
        while (true) {
            const std::size_t pos = rest.find('\x1e');
            if (pos == std::string_view::npos) {
                if (!rest.empty()) {
                    out->permissions.push_back(rest);
                }
                break;
            }
            if (pos > 0) {
                out->permissions.push_back(rest.substr(0, pos));
            }
            rest.remove_prefix(pos + 1);
        }
    }
    return true;
}

}  // namespace unknown::native::protocol
