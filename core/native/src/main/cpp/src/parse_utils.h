#pragma once

#include <cstdint>
#include <string_view>

namespace unknown::native::detail {

/** Lazily splits a record into \x1F-separated fields; views into the record. */
class FieldScanner final {
public:
    explicit FieldScanner(std::string_view record) : rest_(record) {}

    /** Next field, or false when the record is exhausted. */
    bool next(std::string_view* out) {
        if (done_) {
            return false;
        }
        const std::size_t pos = rest_.find(kFieldSeparator);
        if (pos == std::string_view::npos) {
            *out = rest_;
            done_ = true;
            rest_ = {};
            return true;
        }
        *out = rest_.substr(0, pos);
        rest_.remove_prefix(pos + 1);
        return true;
    }

    /** True when every field has been consumed. */
    [[nodiscard]] bool exhausted() const { return done_; }

private:
    static constexpr char kFieldSeparator = '\x1f';

    std::string_view rest_;
    bool done_ = false;
};

/** Strict decimal int32 parse; no leading/trailing whitespace allowed. */
inline bool parseInt32(std::string_view text, std::int32_t* out) noexcept {
    if (text.empty() || text.size() > 11) {
        return false;
    }
    std::size_t i = 0;
    bool negative = false;
    if (text[0] == '-') {
        negative = true;
        i = 1;
        if (text.size() == 1) {
            return false;
        }
    }
    std::int64_t value = 0;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        if (c < '0' || c > '9') {
            return false;
        }
        value = value * 10 + (c - '0');
        if (value > 2147483648LL) {
            return false;
        }
    }
    if (negative) {
        value = -value;
    }
    if (value > 2147483647LL || value < -2147483648LL) {
        return false;
    }
    *out = static_cast<std::int32_t>(value);
    return true;
}

/** Boolean parse: "0" or "1". */
inline bool parseBool(std::string_view text, bool* out) noexcept {
    if (text.size() == 1 && text[0] == '0') {
        *out = false;
        return true;
    }
    if (text.size() == 1 && text[0] == '1') {
        *out = true;
        return true;
    }
    return false;
}

}  // namespace unknown::native::detail
