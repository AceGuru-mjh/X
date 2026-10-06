#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace unknown::native {

/**
 * Growable bitmap with inline storage.
 *
 * Words beyond the inline capacity spill to the heap. Rule bitmaps are built
 * once at compile time; the snapshot bitmap lives inside the reusable
 * EvalScratch, so the evaluation hot path performs no allocations at all
 * once the scratch has warmed up.
 */
template <std::size_t kInlineWords>
class Bitmap final {
public:
    /** Resizes to [bitCount] bits and clears every bit. */
    void reset(std::size_t bitCount) {
        bitCount_ = bitCount;
        const std::size_t words = wordCount();
        if (words > kInlineWords) {
            spill_.assign(words, 0);
        } else {
            spill_.clear();
            for (std::size_t w = 0; w < words; ++w) {
                inlineWords_[w] = 0;
            }
        }
    }

    /** Sets bit [bit]; callers guarantee bit < bitCount(). */
    void set(std::size_t bit) noexcept {
        const std::size_t w = bit >> 6;
        const std::uint64_t mask = 1ULL << (bit & 63);
        if (w < kInlineWords) {
            inlineWords_[w] |= mask;
        } else {
            spill_[w - kInlineWords] |= mask;
        }
    }

    [[nodiscard]] bool test(std::size_t bit) const noexcept {
        const std::size_t w = bit >> 6;
        if (w >= wordCount()) {
            return false;
        }
        const std::uint64_t mask = 1ULL << (bit & 63);
        return (wordAt(w) & mask) != 0;
    }

    /** True when every bit set in [required] is also set here (same width expected). */
    template <std::size_t kOtherWords>
    [[nodiscard]] bool containsAll(const Bitmap<kOtherWords>& required) const noexcept {
        const std::size_t words = minWordCount(required);
        for (std::size_t w = 0; w < words; ++w) {
            const std::uint64_t need = required.wordAt(w);
            if ((wordAt(w) & need) != need) {
                return false;
            }
        }
        return true;
    }

    /** Number of bits set in both bitmaps (same width expected). */
    template <std::size_t kOtherWords>
    [[nodiscard]] std::size_t popcountAnd(const Bitmap<kOtherWords>& other) const noexcept {
        std::size_t total = 0;
        const std::size_t words = minWordCount(other);
        for (std::size_t w = 0; w < words; ++w) {
            total += popcount64(wordAt(w) & other.wordAt(w));
        }
        return total;
    }

    /** Number of bits set. */
    [[nodiscard]] std::size_t popcount() const noexcept {
        std::size_t total = 0;
        const std::size_t words = wordCount();
        for (std::size_t w = 0; w < words; ++w) {
            total += popcount64(wordAt(w));
        }
        return total;
    }

    [[nodiscard]] bool any() const noexcept {
        const std::size_t words = wordCount();
        for (std::size_t w = 0; w < words; ++w) {
            if (wordAt(w) != 0) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::size_t bitCount() const noexcept { return bitCount_; }

    // Word-level accessors; public so differently-parameterized Bitmap
    // instantiations can interoperate in containsAll()/popcountAnd().
    [[nodiscard]] std::size_t wordCount() const noexcept { return (bitCount_ + 63) >> 6; }

    [[nodiscard]] std::uint64_t wordAt(std::size_t w) const noexcept {
        return w < kInlineWords ? inlineWords_[w] : spill_[w - kInlineWords];
    }

private:
    template <std::size_t kOtherWords>
    [[nodiscard]] std::size_t minWordCount(const Bitmap<kOtherWords>& other) const noexcept {
        const std::size_t a = wordCount();
        const std::size_t b = other.wordCount();
        return a < b ? a : b;
    }

    static std::size_t popcount64(std::uint64_t value) noexcept {
        return static_cast<std::size_t>(__builtin_popcountll(value));
    }

    std::array<std::uint64_t, kInlineWords> inlineWords_{};
    std::vector<std::uint64_t> spill_;
    std::size_t bitCount_ = 0;
};

}  // namespace unknown::native
