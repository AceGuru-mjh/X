#include "unknown_native/engine.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>

#include "hash_utils.h"
#include "parse_utils.h"
#include "unknown_native/protocol.h"
#include "unknown_native/sha256.h"

namespace unknown::native {

namespace {

constexpr std::size_t kMaxRuleBlobBytes = 1U << 20;  // 1 MiB of encoded rules
constexpr std::size_t kMaxRules = 50000;
constexpr std::size_t kMatchReserveCap = 4096;
constexpr char kListSeparator = '\x1e';

using detail::FieldScanner;
using detail::parseInt32;
using detail::parseBool;

void splitList(std::string_view text, std::vector<std::string_view>* out) {
    if (text.empty()) {
        return;
    }
    std::string_view rest = text;
    while (true) {
        const std::size_t pos = rest.find(kListSeparator);
        if (pos == std::string_view::npos) {
            if (!rest.empty()) {
                out->push_back(rest);
            }
            return;
        }
        if (pos > 0) {
            out->push_back(rest.substr(0, pos));
        }
        rest.remove_prefix(pos + 1);
    }
}

void markRules(const std::vector<std::uint32_t>& offsets,
               const std::vector<std::uint32_t>& rules,
               std::int32_t group,
               EvalScratch& scratch) {
    const std::size_t begin = offsets[static_cast<std::size_t>(group)];
    const std::size_t end = offsets[static_cast<std::size_t>(group) + 1];
    for (std::size_t k = begin; k < end; ++k) {
        scratch.ruleHits[rules[k]] = 1;
    }
}

}  // namespace

void EvalScratch::resetFor(std::size_t ruleCount, std::size_t permissionBits) {
    ruleHits.assign(ruleCount, 0);
    matchedKeyword.assign(ruleCount, std::string_view{});
    snapshotPermissions.reset(permissionBits);
    matches.clear();
    sortedMatches.clear();
    const std::size_t reserve = (ruleCount < kMatchReserveCap) ? ruleCount : kMatchReserveCap;
    if (matches.capacity() < reserve) {
        matches.reserve(reserve);
    }
    if (sortedMatches.capacity() < reserve) {
        sortedMatches.reserve(reserve);
    }
}

void StringTable::build(std::vector<std::pair<std::string_view, int32_t>> entries) {
    entries_ = std::move(entries);
    count_ = entries_.size();
    std::size_t capacity = 16;
    while (capacity < (count_ + 1) * 2) {
        capacity <<= 1;
    }
    table_.assign(capacity, Slot{0, -1, {}});
    mask_ = capacity - 1;
    for (const auto& [key, payload] : entries_) {
        const std::uint64_t hash = detail::fnv1a64(key);
        std::size_t slot = static_cast<std::size_t>(hash) & mask_;
        while (table_[slot].payload != -1) {
            slot = (slot + 1) & mask_;
        }
        table_[slot] = Slot{hash, payload, key};
    }
}

int32_t StringTable::find(std::string_view key) const noexcept {
    if (table_.empty()) {
        return -1;
    }
    const std::uint64_t hash = detail::fnv1a64(key);
    std::size_t slot = static_cast<std::size_t>(hash) & mask_;
    while (table_[slot].payload != -1) {
        if (table_[slot].hash == hash && table_[slot].key == key) {
            return table_[slot].payload;
        }
        slot = (slot + 1) & mask_;
    }
    return -1;
}

void GroupTable::build(std::vector<std::pair<std::string_view, int32_t>> entries) {
    std::stable_sort(entries.begin(), entries.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    offsets_.clear();
    rules_.clear();
    std::vector<std::pair<std::string_view, int32_t>> uniqueEntries;
    std::size_t group = 0;
    std::size_t i = 0;
    while (i < entries.size()) {
        offsets_.push_back(static_cast<std::uint32_t>(rules_.size()));
        uniqueEntries.emplace_back(entries[i].first, static_cast<std::int32_t>(group));
        std::size_t j = i;
        while (j < entries.size() && entries[j].first == entries[i].first) {
            rules_.push_back(static_cast<std::uint32_t>(entries[j].second));
            ++j;
        }
        ++group;
        i = j;
    }
    offsets_.push_back(static_cast<std::uint32_t>(rules_.size()));
    table_.build(std::move(uniqueEntries));
}

int32_t GroupTable::findGroup(std::string_view key) const noexcept { return table_.find(key); }

std::unique_ptr<CompiledRuleSet> CompiledRuleSet::compile(std::string_view rulesBlob, std::string* error) {
    const auto fail = [error](const std::string& message) -> std::unique_ptr<CompiledRuleSet> {
        if (error != nullptr) {
            *error = message;
        }
        return nullptr;
    };

    if (rulesBlob.size() > kMaxRuleBlobBytes) {
        return fail("rule blob exceeds 1 MiB");
    }

    auto set = std::make_unique<CompiledRuleSet>();
    // Stable storage: every parsed view points into this private copy.
    set->blob_.assign(rulesBlob.begin(), rulesBlob.end());
    const std::string_view blob{set->blob_.data(), set->blob_.size()};

    struct ParsedRule {
        std::string_view id;
        std::string_view name;
        Severity severity = Severity::Low;
        RuleType type = RuleType::PackageName;
        std::string_view pattern;
        bool isRegex = false;
        std::vector<std::string_view> keywords;
        std::vector<std::string_view> required;
        std::vector<std::string_view> anyOf;
        std::int32_t anyOfCount = 0;
        std::string_view sha256;
        std::int32_t maxTargetSdk = 0;
        bool requireDangerousPermissions = true;
    };

    std::vector<ParsedRule> parsed;
    std::vector<std::pair<std::string_view, int32_t>> exactPackageEntries;
    std::vector<std::pair<std::string_view, int32_t>> keywordEntries;
    std::size_t comboPermissionCount = 0;

    // ---- pass 1: parse lines -------------------------------------------
    std::size_t lineNumber = 0;
    std::size_t consumed = 0;
    while (consumed < blob.size()) {
        ++lineNumber;
        std::string_view line = blob.substr(consumed);
        const std::size_t newline = line.find('\n');
        if (newline != std::string_view::npos) {
            line = line.substr(0, newline);
            consumed += newline + 1;
        } else {
            consumed = blob.size();
        }
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        if (line.empty()) {
            continue;  // tolerate blank lines
        }
        if (parsed.size() >= kMaxRules) {
            return fail("too many rules (limit 50000)");
        }

        const std::string where = "line " + std::to_string(lineNumber);
        FieldScanner scanner(line);

        std::string_view typeCode;
        if (!scanner.next(&typeCode) || typeCode.size() != 1) {
            return fail(where + ": missing rule type code");
        }

        ParsedRule rule;
        std::string_view severityText;
        if (!scanner.next(&rule.id) || !scanner.next(&rule.name) || !scanner.next(&severityText)) {
            return fail(where + ": rule needs type, id, name and severity fields");
        }
        if (rule.id.empty()) {
            return fail(where + ": rule id is empty");
        }
        std::int32_t severity = 0;
        if (!parseInt32(severityText, &severity) || severity < 0 || severity > 3) {
            return fail(where + ": severity must be one of 0..3");
        }
        rule.severity = static_cast<Severity>(severity);

        switch (typeCode[0]) {
            case 'P': {
                rule.type = RuleType::PackageName;
                std::string_view pattern;
                std::string_view isRegexText;
                if (!scanner.next(&pattern) || !scanner.next(&isRegexText)) {
                    return fail(where + ": package rule needs pattern and isRegex fields");
                }
                if (pattern.empty()) {
                    return fail(where + ": package pattern is empty");
                }
                if (!parseBool(isRegexText, &rule.isRegex)) {
                    return fail(where + ": isRegex must be 0 or 1");
                }
                rule.pattern = pattern;
                if (!rule.isRegex) {
                    exactPackageEntries.emplace_back(pattern, static_cast<std::int32_t>(parsed.size()));
                }
                break;
            }
            case 'K': {
                rule.type = RuleType::LabelKeyword;
                std::string_view keywordsText;
                if (!scanner.next(&keywordsText)) {
                    return fail(where + ": keyword rule needs a keywords field");
                }
                splitList(keywordsText, &rule.keywords);
                if (rule.keywords.empty()) {
                    return fail(where + ": keyword rule has no keywords");
                }
                for (const auto keyword : rule.keywords) {
                    if (keyword.empty()) {
                        return fail(where + ": keyword rule contains an empty keyword");
                    }
                    keywordEntries.emplace_back(keyword, static_cast<std::int32_t>(parsed.size()));
                }
                break;
            }
            case 'C': {
                rule.type = RuleType::PermissionCombo;
                std::string_view requiredText;
                std::string_view anyOfText;
                std::string_view anyOfCountText;
                if (!scanner.next(&requiredText) || !scanner.next(&anyOfText) || !scanner.next(&anyOfCountText)) {
                    return fail(where + ": combo rule needs required, anyOf and anyOfCount fields");
                }
                splitList(requiredText, &rule.required);
                splitList(anyOfText, &rule.anyOf);
                std::int32_t anyOfCount = 0;
                if (!parseInt32(anyOfCountText, &anyOfCount) || anyOfCount < 0) {
                    return fail(where + ": anyOfCount must be a non-negative integer");
                }
                if (anyOfCount > static_cast<std::int32_t>(rule.anyOf.size())) {
                    return fail(where + ": anyOfCount exceeds the anyOf list size");
                }
                rule.anyOfCount = anyOfCount;
                comboPermissionCount += rule.required.size() + rule.anyOf.size();
                break;
            }
            case 'H': {
                rule.type = RuleType::ApkHash;
                std::string_view sha256;
                if (!scanner.next(&sha256)) {
                    return fail(where + ": hash rule needs a sha256 field");
                }
                if (!isValidSha256Hex(sha256)) {
                    return fail(where + ": sha256 must be 64 hex characters");
                }
                rule.sha256 = sha256;
                break;
            }
            case 'T': {
                rule.type = RuleType::TargetSdk;
                std::string_view maxTargetSdkText;
                std::string_view requireDangerousText;
                if (!scanner.next(&maxTargetSdkText) || !scanner.next(&requireDangerousText)) {
                    return fail(where + ": targetSdk rule needs maxTargetSdk and requireDangerous fields");
                }
                if (!parseInt32(maxTargetSdkText, &rule.maxTargetSdk)) {
                    return fail(where + ": maxTargetSdk is not an integer");
                }
                if (!parseBool(requireDangerousText, &rule.requireDangerousPermissions)) {
                    return fail(where + ": requireDangerousPermissions must be 0 or 1");
                }
                break;
            }
            default:
                return fail(where + ": unknown rule type code '" + std::string(typeCode) + "'");
        }

        if (!scanner.exhausted()) {
            return fail(where + ": too many fields for this rule type");
        }
        parsed.push_back(std::move(rule));
    }

    // ---- pass 2: build compiled rules ----------------------------------
    set->rules_.reserve(parsed.size());
    set->permissions_.reserve(comboPermissionCount + 16);

    std::size_t hashStorageBytes = 0;
    for (const auto& rule : parsed) {
        if (rule.type == RuleType::ApkHash) {
            hashStorageBytes += 64;
        }
    }
    // Reserve once so views taken below stay valid while appending.
    set->sha256Storage_.reserve(hashStorageBytes);

    std::vector<std::pair<std::string_view, int32_t>> hashEntries;
    for (std::size_t i = 0; i < parsed.size(); ++i) {
        const ParsedRule& rule = parsed[i];
        CompiledRule compiled;
        compiled.meta = RuleMetaView{rule.id, rule.name, rule.severity};
        compiled.type = rule.type;

        switch (rule.type) {
            case RuleType::PackageName: {
                compiled.pattern = rule.pattern;
                compiled.isRegex = rule.isRegex;
                if (rule.isRegex) {
                    std::string regexError;
                    if (!RegexLite::compile(rule.pattern, &compiled.regex, &regexError)) {
                        return fail("rule '" + std::string(rule.id) + "': bad regex: " + regexError);
                    }
                    set->regexPackageRules_.push_back(static_cast<std::uint32_t>(i));
                }
                break;
            }
            case RuleType::LabelKeyword:
                break;  // wired to the automaton below
            case RuleType::PermissionCombo: {
                compiled.anyOfCount = rule.anyOfCount;
                for (const auto permission : rule.required) {
                    set->permissions_.intern(permission);
                }
                for (const auto permission : rule.anyOf) {
                    set->permissions_.intern(permission);
                }
                break;
            }
            case RuleType::ApkHash: {
                char folded[64];
                if (!normalizeSha256Hex(rule.sha256, folded)) {
                    return fail("rule '" + std::string(rule.id) + "': sha256 must be 64 hex characters");
                }
                const std::size_t offset = set->sha256Storage_.size();
                set->sha256Storage_.append(folded, 64);
                compiled.sha256Hex = std::string_view{set->sha256Storage_.data() + offset, 64};
                hashEntries.emplace_back(compiled.sha256Hex, static_cast<std::int32_t>(i));
                break;
            }
            case RuleType::TargetSdk: {
                compiled.maxTargetSdk = rule.maxTargetSdk;
                compiled.requireDangerousPermissions = rule.requireDangerousPermissions;
                break;
            }
        }
        set->rules_.push_back(std::move(compiled));
    }

    // ---- pass 3: permission bitmaps (index is final now) ----------------
    const std::size_t permissionBits = set->permissions_.size();
    for (std::size_t i = 0; i < parsed.size(); ++i) {
        if (parsed[i].type != RuleType::PermissionCombo) {
            continue;
        }
        CompiledRule& compiled = set->rules_[i];
        compiled.requiredPerms.reset(permissionBits);
        compiled.anyOfPerms.reset(permissionBits);
        for (const auto permission : parsed[i].required) {
            const std::int32_t id = set->permissions_.find(permission);
            if (id < 0) {
                return fail("internal error: permission vanished from the index");
            }
            compiled.requiredPerms.set(static_cast<std::size_t>(id));
        }
        for (const auto permission : parsed[i].anyOf) {
            const std::int32_t id = set->permissions_.find(permission);
            if (id < 0) {
                return fail("internal error: permission vanished from the index");
            }
            compiled.anyOfPerms.set(static_cast<std::size_t>(id));
        }
    }

    // ---- keyword automaton with case-folded, deduplicated patterns ------
    // Fold every keyword to its lowercase automaton form FIRST (with one
    // stable storage allocation) so keywords differing only in ASCII case
    // merge into a single pattern whose group covers all of their rules.
    std::size_t keywordBytes = 0;
    for (const auto& [keyword, ruleIndex] : keywordEntries) {
        keywordBytes += keyword.size();
    }
    set->keywordStorage_.reserve(keywordBytes);
    for (auto& [keyword, ruleIndex] : keywordEntries) {
        const std::size_t offset = set->keywordStorage_.size();
        for (const char c : keyword) {
            set->keywordStorage_.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
        }
        keyword = std::string_view{set->keywordStorage_.data() + offset, keyword.size()};
    }
    std::stable_sort(keywordEntries.begin(), keywordEntries.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    set->keywordPatterns_.clear();
    set->patternOffsets_.clear();
    set->patternRules_.clear();
    std::size_t entry = 0;
    while (entry < keywordEntries.size()) {
        set->patternOffsets_.push_back(static_cast<std::uint32_t>(set->patternRules_.size()));
        set->keywordPatterns_.push_back(keywordEntries[entry].first);
        std::size_t scan = entry;
        while (scan < keywordEntries.size() && keywordEntries[scan].first == keywordEntries[entry].first) {
            set->patternRules_.push_back(static_cast<std::uint32_t>(keywordEntries[scan].second));
            ++scan;
        }
        entry = scan;
    }
    set->patternOffsets_.push_back(static_cast<std::uint32_t>(set->patternRules_.size()));

    std::string automatonError;
    if (!set->keywords_.build(set->keywordPatterns_, &automatonError)) {
        return fail("keyword automaton: " + automatonError);
    }

    set->exactPackages_.build(std::move(exactPackageEntries));
    set->hashTable_.build(std::move(hashEntries));
    return set;
}

void CompiledRuleSet::evaluate(const Snapshot& snapshot, EvalScratch& scratch, Verdict& out) const {
    scratch.resetFor(rules_.size(), permissions_.size());

    // 1) exact package-name rules
    if (const std::int32_t group = exactPackages_.findGroup(snapshot.packageName); group >= 0) {
        markRules(exactPackages_.offsets(), exactPackages_.rules(), group, scratch);
    }

    // 2) regex package-name rules
    for (const std::uint32_t ruleIndex : regexPackageRules_) {
        const CompiledRule& rule = rules_[ruleIndex];
        if (rule.regex.search(snapshot.packageName)) {
            scratch.ruleHits[ruleIndex] = 1;
        }
    }

    // 3) keyword rules: a single scan of the app label
    if (!keywords_.empty() && !snapshot.label.empty()) {
        keywords_.scan(snapshot.label, [&](AhoCorasick::PatternId pattern, std::size_t byteOffset) {
            (void)byteOffset;
            const std::uint32_t begin = patternOffsets_[static_cast<std::size_t>(pattern)];
            const std::uint32_t end = patternOffsets_[static_cast<std::size_t>(pattern) + 1];
            const std::string_view keyword = keywordPatterns_[static_cast<std::size_t>(pattern)];
            for (std::uint32_t k = begin; k < end; ++k) {
                const std::uint32_t ruleIndex = patternRules_[k];
                scratch.ruleHits[ruleIndex] = 1;
                scratch.matchedKeyword[ruleIndex] = keyword;
            }
        });
    }

    // 4) snapshot permission bitmap + dangerous-permission flag
    bool hasDangerousPermission = false;
    for (const auto permission : snapshot.permissions) {
        const std::int32_t id = permissions_.find(permission);
        if (id >= 0) {
            scratch.snapshotPermissions.set(static_cast<std::size_t>(id));
        }
        if (!hasDangerousPermission && isDangerousPermission(permission)) {
            hasDangerousPermission = true;
        }
    }

    // 5) permission combo rules
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const CompiledRule& rule = rules_[i];
        if (rule.type != RuleType::PermissionCombo) {
            continue;
        }
        if (!scratch.snapshotPermissions.containsAll(rule.requiredPerms)) {
            continue;
        }
        if (rule.anyOfCount > 0 &&
            scratch.snapshotPermissions.popcountAnd(rule.anyOfPerms) < static_cast<std::size_t>(rule.anyOfCount)) {
            continue;
        }
        scratch.ruleHits[i] = 1;
    }

    // 6) APK hash rules
    if (!snapshot.sha256Hex.empty()) {
        if (normalizeSha256Hex(snapshot.sha256Hex, scratch.hashBuffer)) {
            if (const std::int32_t group = hashTable_.findGroup(std::string_view{scratch.hashBuffer, 64}); group >= 0) {
                markRules(hashTable_.offsets(), hashTable_.rules(), group, scratch);
            }
        }
    }

    // 7) targetSdk rules
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const CompiledRule& rule = rules_[i];
        if (rule.type != RuleType::TargetSdk) {
            continue;
        }
        if (snapshot.targetSdk > rule.maxTargetSdk) {
            continue;
        }
        if (rule.requireDangerousPermissions && !hasDangerousPermission) {
            continue;
        }
        scratch.ruleHits[i] = 1;
    }

    // 8) aggregate in rule order
    std::int32_t score = 0;
    scratch.matches.clear();
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        if (scratch.ruleHits[i] == 0) {
            continue;
        }
        const CompiledRule& rule = rules_[i];
        score += kSeverityScores[static_cast<std::size_t>(rule.meta.severity)];
        MatchedRuleView match;
        match.ruleId = rule.meta.id;
        match.ruleName = rule.meta.name;
        match.severity = rule.meta.severity;
        composeDetail(rule, i, snapshot, scratch, &match);
        scratch.matches.push_back(match);
    }

    // severity-descending stable order (counting placement, no comparator sort)
    std::size_t counts[4] = {0, 0, 0, 0};
    for (const auto& match : scratch.matches) {
        ++counts[static_cast<std::size_t>(match.severity)];
    }
    std::size_t position[4];
    position[3] = 0;
    position[2] = counts[3];
    position[1] = counts[3] + counts[2];
    position[0] = counts[3] + counts[2] + counts[1];
    scratch.sortedMatches.assign(scratch.matches.size(), MatchedRuleView{});
    for (const auto& match : scratch.matches) {
        scratch.sortedMatches[position[static_cast<std::size_t>(match.severity)]++] = match;
    }

    out.score = score;
    out.matchCount = static_cast<std::uint32_t>(scratch.sortedMatches.size());
    out.matches = scratch.sortedMatches.empty() ? nullptr : scratch.sortedMatches.data();
    out.level = (score >= kDangerousScoreThreshold) ? VerdictLevel::Dangerous
                                                    : ((score > 0) ? VerdictLevel::Suspicious : VerdictLevel::Clean);
}

void CompiledRuleSet::composeDetail(const CompiledRule& rule,
                                    std::size_t ruleIndex,
                                    const Snapshot& snapshot,
                                    const EvalScratch& scratch,
                                    MatchedRuleView* out) const noexcept {
    int written = 0;
    switch (rule.type) {
        case RuleType::PackageName:
            written = std::snprintf(out->detail,
                                    sizeof(out->detail),
                                    rule.isRegex ? "包名正则命中：%.*s" : "包名精确命中：%.*s",
                                    static_cast<int>(rule.pattern.size()),
                                    rule.pattern.data());
            break;
        case RuleType::LabelKeyword: {
            const std::string_view keyword = scratch.matchedKeyword[ruleIndex];
            if (keyword.empty()) {
                written = std::snprintf(out->detail, sizeof(out->detail), "应用名关键词命中");
            } else {
                written = std::snprintf(out->detail,
                                        sizeof(out->detail),
                                        "应用名关键词命中：%.*s",
                                        static_cast<int>(keyword.size()),
                                        keyword.data());
            }
            break;
        }
        case RuleType::PermissionCombo: {
            const std::size_t requiredCount = rule.requiredPerms.popcount();
            if (rule.anyOfCount > 0) {
                const std::size_t hitCount = scratch.snapshotPermissions.popcountAnd(rule.anyOfPerms);
                written = std::snprintf(out->detail,
                                        sizeof(out->detail),
                                        "权限组合命中：必需 %zu 项全含，可选命中 %zu/%d",
                                        requiredCount,
                                        hitCount,
                                        static_cast<int>(rule.anyOfCount));
            } else {
                written = std::snprintf(out->detail,
                                        sizeof(out->detail),
                                        "权限组合命中：必需 %zu 项全含",
                                        requiredCount);
            }
            break;
        }
        case RuleType::ApkHash:
            written = std::snprintf(out->detail,
                                    sizeof(out->detail),
                                    "APK SHA-256 命中：%.*s",
                                    static_cast<int>(rule.sha256Hex.size()),
                                    rule.sha256Hex.data());
            break;
        case RuleType::TargetSdk:
            if (rule.requireDangerousPermissions) {
                written = std::snprintf(out->detail,
                                        sizeof(out->detail),
                                        "targetSdk=%d（上限 %d），含敏感权限",
                                        static_cast<int>(snapshot.targetSdk),
                                        static_cast<int>(rule.maxTargetSdk));
            } else {
                written = std::snprintf(out->detail,
                                        sizeof(out->detail),
                                        "targetSdk=%d（上限 %d）",
                                        static_cast<int>(snapshot.targetSdk),
                                        static_cast<int>(rule.maxTargetSdk));
            }
            break;
    }
    if (written < 0) {
        written = 0;
    }
    out->detailLength = static_cast<std::uint16_t>(
        static_cast<std::size_t>(written) >= sizeof(out->detail) ? sizeof(out->detail) - 1 : static_cast<std::size_t>(written));
}

}  // namespace unknown::native
