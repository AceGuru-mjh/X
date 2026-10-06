#pragma once

#include <cstdio>
#include <string>
#include <string_view>
#include <type_traits>

namespace ut {

inline int failures = 0;

inline std::string printable(const char* s) { return s != nullptr ? std::string(s) : std::string("<null>"); }

inline std::string printable(const std::string& s) { return "\"" + s + "\""; }

inline std::string printable(std::string_view s) { return "\"" + std::string(s) + "\""; }

inline std::string printable(bool b) { return b ? "true" : "false"; }

template <typename T, typename = std::enable_if_t<std::is_integral_v<T> || std::is_floating_point_v<T>>>
inline std::string printable(T value) {
    return std::to_string(value);
}

}  // namespace ut

#define UT_CHECK(condition)                                                                        \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "%s:%d: FAILED check: %s\n", __FILE__, __LINE__, #condition);     \
            ++ut::failures;                                                                        \
        }                                                                                          \
    } while (false)

#define UT_CHECK_EQ(actual, expected)                                                              \
    do {                                                                                           \
        const auto actualValue = (actual);                                                         \
        const auto expectedValue = (expected);                                                     \
        if (!(actualValue == expectedValue)) {                                                     \
            std::fprintf(stderr,                                                                   \
                         "%s:%d: FAILED %s == %s\n  actual:   %s\n  expected: %s\n",              \
                         __FILE__,                                                                 \
                         __LINE__,                                                                 \
                         #actual,                                                                 \
                         #expected,                                                                \
                         ut::printable(actualValue).c_str(),                                       \
                         ut::printable(expectedValue).c_str());                                    \
            ++ut::failures;                                                                        \
        }                                                                                          \
    } while (false)

/** Ends a test binary; returns failure count through the process exit code. */
#define UT_END()                                                                                   \
    do {                                                                                           \
        if (ut::failures == 0) {                                                                   \
            std::fprintf(stderr, "all checks passed\n");                                           \
            return 0;                                                                              \
        }                                                                                           \
        std::fprintf(stderr, "%d check(s) failed\n", ut::failures);                                 \
        return 1;                                                                                  \
    } while (false)
