#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "unknown_native/aho_corasick.h"
#include "unknown_native/bitmap.h"
#include "unknown_native/permission_index.h"
#include "unknown_native/protocol.h"
#include "unknown_native/regex_lite.h"
#include "unknown_native/rule_types.h"

namespace unknown::native {

struct RuleMetaView {
    std::string_view id;
    std::string_view name;
    Severity severity = Severity::Low;
};

/** One rule hit with a human-readable detail — mirrors MatchedRule in core/model. */
struct MatchedRuleView {
    std::string_view ruleId;
    std::string_view ruleName;
    Severity severity = Severity::Low;
    std::uint16_t detailLength = 0;
    char detail[168] = {};
};

/** Engine verdict — mirrors ScanVerdict in core/model. */
struct Verdict {
    std::int32_t score = 0;
    VerdictLevel level = VerdictLevel::Clean;
    std::uint32_t matchCount = 0;
    /** Points into the scratch that produced the verdict; valid until the next evaluate(). */
    const MatchedRuleView* matches = nullptr;
};

/**
 * Reusable per-thread evaluation state.
 *
 * Warm one scratch up (a single evaluate() call is enough) and every further
 * call runs without touching the allocator. The JNI bridge keeps a
 * thread-local scratch so the steady state on Android is allocation-free.
 */
class EvalScratch final {
public:
    void resetFor(std::size_t ruleCount, std::size_t permissionBits);

    // Owned by the engine; public for simplicity, not part of the public API.
    std::vector<std::uint8_t> ruleHits;
    std::vector<std::string_view> matchedKeyword;
    Bitmap<8> snapshotPermissions;
    std::vector<MatchedRuleView> matches;
    std::vector<MatchedRuleView> sortedMatches;
    char hashBuffer[64] = {};
};

/** Open-addressing string view table; lookups never allocate. */
class StringTable final {
public:
    void build(std::vector<std::pair<std::string_view, int32_t>> entries);

    /** Payload of the entry equal to [key], or -1 when absent. */
    [[nodiscard]] int32_t find(std::string_view key) const noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return count_; }

private:
    struct Slot {
        std::uint64_t hash;
        std::int32_t payload;
        std::string_view key;
    };

    std::vector<Slot> table_;  // power-of-two sized; payload == -1 marks an empty slot
    std::vector<std::pair<std::string_view, int32_t>> entries_;
    std::size_t count_ = 0;
    std::uint64_t mask_ = 0;
};

/**
 * Unique-key lookup whose keys may carry several rules (duplicate exact
 * package names, identical hashes). Rules of group g live in
 * rules()[offsets()[g], offsets()[g + 1]).
 */
class GroupTable final {
public:
    /** Builds groups from (key, ruleIndex) pairs; views must stay stable. */
    void build(std::vector<std::pair<std::string_view, int32_t>> entries);

    /** Group id for [key], or -1 when absent. */
    [[nodiscard]] int32_t findGroup(std::string_view key) const noexcept;

    [[nodiscard]] const std::vector<std::uint32_t>& rules() const noexcept { return rules_; }

    [[nodiscard]] const std::vector<std::uint32_t>& offsets() const noexcept { return offsets_; }

    [[nodiscard]] std::size_t groupCount() const noexcept { return offsets_.size() <= 1 ? 0 : offsets_.size() - 1; }

private:
    StringTable table_;
    std::vector<std::uint32_t> offsets_;
    std::vector<std::uint32_t> rules_;
};

/**
 * The compiled detection core of Unknown Security.
 *
 * A rule set is compiled once from the protocol blob produced by
 * NativeRuleCodec on the Kotlin side. The compiled form is immutable and
 * safe to use from multiple threads concurrently; each thread should use
 * its own EvalScratch.
 *
 * Evaluation covers every rule kind of core/model:
 *   - PackageNameRule      exact hash lookup or RegexLite search
 *   - LabelKeywordRule     one Aho-Corasick scan of the app label
 *   - PermissionComboRule  dense bitmap containment + popcount check
 *   - ApkHashRule          normalized SHA-256 table lookup
 *   - TargetSdkRule        integer bound + dangerous-permission heuristic
 */
class CompiledRuleSet final {
public:
    /**
     * Compiles [rulesBlob] (one rule per line, see docs/NATIVE_ENGINE.md).
     * Returns nullptr and fills [error] when any line is malformed.
     */
    static std::unique_ptr<CompiledRuleSet> compile(std::string_view rulesBlob, std::string* error);

    /** Runs the full matching pipeline; see Verdict for the result shape. */
    void evaluate(const Snapshot& snapshot, EvalScratch& scratch, Verdict& out) const;

    [[nodiscard]] std::size_t ruleCount() const noexcept { return rules_.size(); }

    [[nodiscard]] std::size_t permissionCount() const noexcept { return permissions_.size(); }

    /** Score at or above this bound maps to VerdictLevel::Dangerous. */
    static constexpr std::int32_t kDangerousScoreThreshold = 50;

private:
    struct CompiledRule {
        RuleMetaView meta;
        RuleType type = RuleType::PackageName;
        // PackageNameRule
        std::string_view pattern;
        bool isRegex = false;
        RegexLite regex;
        // PermissionComboRule
        Bitmap<4> requiredPerms;
        Bitmap<4> anyOfPerms;
        std::int32_t anyOfCount = 0;
        // ApkHashRule (normalized lowercase)
        std::string_view sha256Hex;
        // TargetSdkRule
        std::int32_t maxTargetSdk = 0;
        bool requireDangerousPermissions = true;
    };

    void composeDetail(const CompiledRule& rule,
                       std::size_t ruleIndex,
                       const Snapshot& snapshot,
                       const EvalScratch& scratch,
                       MatchedRuleView* out) const noexcept;

    // A private copy of the input blob: every string view below points into
    // this stable storage, so no per-string copies are needed at all.
    std::vector<char> blob_;
    // Case-folded SHA-256 literals; capacity is reserved up front so the
    // views taken during compilation stay valid.
    std::string sha256Storage_;
    // Case-folded keywords; same reserve-up-front contract. Keywords are
    // folded BEFORE deduplication so two rules whose keywords differ only
    // in ASCII case share one folded automaton pattern and both still hit.
    std::string keywordStorage_;

    std::vector<CompiledRule> rules_;
    std::vector<std::uint32_t> regexPackageRules_;

    AhoCorasick keywords_;
    std::vector<std::string_view> keywordPatterns_;
    // CSR mapping: pattern p -> rules [patternRules_[patternOffsets_[p]], patternOffsets_[p + 1])
    std::vector<std::uint32_t> patternOffsets_;
    std::vector<std::uint32_t> patternRules_;

    PermissionIndex permissions_;
    GroupTable exactPackages_;
    GroupTable hashTable_;
};

}  // namespace unknown::native
