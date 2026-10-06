#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace unknown::native {

/**
 * Small backtracking regular-expression engine covering the subset used by
 * package-name detection rules: literals, '.', character classes, groups,
 * alternation, greedy quantifiers (* + ? {m,n}) and ^/$ anchors.
 *
 * Compiled programs are plain instruction vectors; matching never allocates
 * and is protected by a step budget, so even pathological patterns return
 * quickly instead of hanging. Patterns are byte-oriented, which is exactly
 * right for ASCII package names.
 */
class RegexLite final {
public:
    /**
     * Compiles [pattern] into [out]. Returns false and fills [error] with a
     * human-readable reason for every rejected pattern.
     */
    static bool compile(std::string_view pattern, RegexLite* out, std::string* error);

    /** Unanchored search — true when the pattern occurs anywhere in [text]. */
    [[nodiscard]] bool search(std::string_view text) const noexcept;

    /** Number of instructions; exposed for tests and debugging. */
    [[nodiscard]] std::size_t instructionCount() const noexcept { return prog_.size(); }

    RegexLite() = default;
    RegexLite(const RegexLite&) = default;
    RegexLite& operator=(const RegexLite&) = default;
    RegexLite(RegexLite&&) = default;
    RegexLite& operator=(RegexLite&&) = default;

private:
    enum class Op : std::uint8_t {
        Char,
        Any,
        Class,
        Split,
        Jmp,
        Match,
        AssertStart,
        AssertEnd,
    };

    struct Inst {
        Op op;
        std::uint8_t ch;
        std::uint32_t cls;
        std::int32_t x;
        std::int32_t y;
    };

    bool matchRec(std::int32_t pc,
                  std::size_t pos,
                  std::string_view text,
                  std::uint32_t* stepsLeft,
                  std::uint32_t depthLeft) const noexcept;

    std::vector<Inst> prog_;
    std::vector<std::vector<std::uint8_t>> classes_;
};

}  // namespace unknown::native
