#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace unknown::native {

/**
 * Compact Aho-Corasick multi-pattern automaton.
 *
 * Built once from every keyword of every LabelKeywordRule; scanning an app
 * label once finds ALL keyword hits, no matter how many keyword rules the
 * set contains. ASCII letters are case-folded on both sides; UTF-8 content
 * (for example Chinese keywords) matches byte-exactly, which is correct for
 * UTF-8 substring search.
 *
 * scan() performs no allocations: the automaton is flattened into nodes with
 * sorted edge lists plus pre-computed failure and output links.
 */
class AhoCorasick final {
public:
    using PatternId = int32_t;

    /**
     * Builds the automaton from [patterns].
     *
     * Patterns must be non-empty and UNIQUE — the engine layer deduplicates
     * keywords before calling this. The pattern views are retained (not
     * copied), so the backing storage must outlive the matcher.
     * Returns false and fills [error] when a pattern is empty.
     */
    bool build(const std::vector<std::string_view>& patterns, std::string* error);

    /** True when there is nothing to match — scan() is a no-op then. */
    [[nodiscard]] bool empty() const noexcept { return nodes_.size() <= 1; }

    /**
     * Scans [text] and invokes onHit(patternId, byteOffset) for every
     * occurrence of every pattern, overlaps included. [byteOffset] is the
     * index of the FIRST byte of the occurrence.
     */
    template <typename Fn>
    void scan(std::string_view text, Fn&& onHit) const {
        if (empty() || text.empty()) {
            return;
        }
        int32_t state = kRoot;
        for (std::size_t i = 0; i < text.size(); ++i) {
            const std::uint8_t byte = foldByte(static_cast<std::uint8_t>(text[i]));
            state = step(state, byte);
            for (int32_t out = state; out != kNoNode; out = outputLink_[static_cast<std::size_t>(out)]) {
                const PatternId id = nodes_[static_cast<std::size_t>(out)].patternId;
                if (id >= 0) {
                    onHit(id, i + 1 - patternLengths_[static_cast<std::size_t>(id)]);
                }
            }
        }
    }

    [[nodiscard]] std::size_t patternCount() const noexcept { return patternCount_; }

    [[nodiscard]] std::size_t nodeCount() const noexcept { return nodes_.size(); }

private:
    struct Node {
        // Sorted (byte, target) edge list — small and cache friendly.
        std::vector<std::pair<std::uint8_t, int32_t>> edges;
        PatternId patternId = -1;
    };

    static constexpr int32_t kRoot = 0;
    static constexpr int32_t kNoNode = -1;

    [[nodiscard]] static std::uint8_t foldByte(std::uint8_t c) noexcept {
        return (c >= 'A' && c <= 'Z') ? static_cast<std::uint8_t>(c - 'A' + 'a') : c;
    }

    /** Advances from [state] on [byte] following failure links. */
    [[nodiscard]] int32_t step(int32_t state, std::uint8_t byte) const noexcept;

    /** Binary-searches the edge list of [node] for [byte]. */
    [[nodiscard]] int32_t findEdge(int32_t node, std::uint8_t byte) const noexcept;

    std::vector<Node> nodes_;
    std::vector<int32_t> fail_;
    std::vector<int32_t> outputLink_;
    std::vector<std::uint32_t> patternLengths_;
    std::size_t patternCount_ = 0;
};

}  // namespace unknown::native
