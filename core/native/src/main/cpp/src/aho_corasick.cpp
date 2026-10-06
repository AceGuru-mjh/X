#include "unknown_native/aho_corasick.h"

namespace unknown::native {

int32_t AhoCorasick::findEdge(int32_t node, std::uint8_t byte) const noexcept {
    const auto& edges = nodes_[static_cast<std::size_t>(node)].edges;
    std::size_t lo = 0;
    std::size_t hi = edges.size();
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        const std::uint8_t key = edges[mid].first;
        if (key < byte) {
            lo = mid + 1;
        } else if (key > byte) {
            hi = mid;
        } else {
            return edges[mid].second;
        }
    }
    return kNoNode;
}

int32_t AhoCorasick::step(int32_t state, std::uint8_t byte) const noexcept {
    int32_t node = state;
    while (true) {
        const int32_t next = findEdge(node, byte);
        if (next != kNoNode) {
            return next;
        }
        if (node == kRoot) {
            return kRoot;
        }
        node = fail_[static_cast<std::size_t>(node)];
    }
}

bool AhoCorasick::build(const std::vector<std::string_view>& patterns, std::string* error) {
    nodes_.clear();
    fail_.clear();
    outputLink_.clear();
    patternLengths_.clear();
    patternCount_ = patterns.size();
    nodes_.emplace_back();  // root

    for (std::size_t p = 0; p < patterns.size(); ++p) {
        const std::string_view pattern = patterns[p];
        if (pattern.empty()) {
            if (error != nullptr) {
                *error = "empty keyword at pattern index " + std::to_string(p);
            }
            nodes_.clear();  // never leave a half-built automaton behind
            return false;
        }
        patternLengths_.push_back(static_cast<std::uint32_t>(pattern.size()));
        int32_t current = kRoot;
        for (const char c : pattern) {
            const std::uint8_t byte = foldByte(static_cast<std::uint8_t>(c));
            const int32_t existing = findEdge(current, byte);
            if (existing != kNoNode) {
                current = existing;
                continue;
            }
            // Insertion position inside the sorted edge list of [current].
            std::size_t pos = 0;
            const auto& edges = nodes_[static_cast<std::size_t>(current)].edges;
            while (pos < edges.size() && edges[pos].first < byte) {
                ++pos;
            }
            // Adding a node may reallocate nodes_; compute indices first.
            const int32_t newNode = static_cast<int32_t>(nodes_.size());
            nodes_.emplace_back();
            auto& mutableEdges = nodes_[static_cast<std::size_t>(current)].edges;
            mutableEdges.insert(mutableEdges.begin() + static_cast<std::ptrdiff_t>(pos),
                                std::make_pair(byte, newNode));
            current = newNode;
        }
        nodes_[static_cast<std::size_t>(current)].patternId = static_cast<PatternId>(p);
    }

    // Breadth-first construction of failure and output links.
    fail_.assign(nodes_.size(), kRoot);
    outputLink_.assign(nodes_.size(), kNoNode);

    std::vector<int32_t> queue;
    queue.reserve(nodes_.size());
    for (const auto& edge : nodes_[static_cast<std::size_t>(kRoot)].edges) {
        queue.push_back(edge.second);  // depth-1 nodes fail to root
    }
    for (std::size_t head = 0; head < queue.size(); ++head) {
        const int32_t node = queue[head];
        for (const auto& [byte, child] : nodes_[static_cast<std::size_t>(node)].edges) {
            int32_t from = fail_[static_cast<std::size_t>(node)];
            int32_t target = kNoNode;
            while (true) {
                target = findEdge(from, byte);
                if (target != kNoNode && target != child) {
                    break;
                }
                if (target == child) {
                    // Can only happen for depth-1 children; they fail to root.
                    target = kRoot;
                    break;
                }
                if (from == kRoot) {
                    target = kRoot;
                    break;
                }
                from = fail_[static_cast<std::size_t>(from)];
            }
            fail_[static_cast<std::size_t>(child)] = target;
            if (nodes_[static_cast<std::size_t>(target)].patternId >= 0) {
                outputLink_[static_cast<std::size_t>(child)] = target;
            } else {
                outputLink_[static_cast<std::size_t>(child)] = outputLink_[static_cast<std::size_t>(target)];
            }
            queue.push_back(child);
        }
    }
    return true;
}

}  // namespace unknown::native
