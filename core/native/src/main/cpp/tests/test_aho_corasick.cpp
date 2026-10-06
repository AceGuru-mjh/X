#include "test_support.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "unknown_native/aho_corasick.h"

using unknown::native::AhoCorasick;

namespace {

std::vector<std::string_view> views(const std::vector<std::string>& strings) {
    return {strings.begin(), strings.end()};
}

/** Collects (patternId, offset) hits produced by a scan. */
std::vector<std::pair<AhoCorasick::PatternId, std::size_t>> collect(const AhoCorasick& matcher,
                                                                    std::string_view text) {
    std::vector<std::pair<AhoCorasick::PatternId, std::size_t>> hits;
    matcher.scan(text, [&hits](AhoCorasick::PatternId id, std::size_t offset) { hits.emplace_back(id, offset); });
    return hits;
}

}  // namespace

int main() {
    // --- classic textbook automaton -------------------------------------------
    {
        const std::vector<std::string> patterns = {"he", "she", "his", "hers"};
        AhoCorasick matcher;
        std::string error;
        UT_CHECK(matcher.build(views(patterns), &error));
        UT_CHECK_EQ(matcher.patternCount(), static_cast<std::size_t>(4));

        // "ushers" contains "she" (offset 1), "he" (offset 2) and "hers" (offset 2).
        const auto hits = collect(matcher, "ushers");
        UT_CHECK_EQ(hits.size(), static_cast<std::size_t>(3));
        // pattern ids: he=0, she=1, his=2, hers=3
        bool sawShe = false;
        bool sawHe = false;
        bool sawHers = false;
        for (const auto& [id, offset] : hits) {
            if (id == 0 && offset == 2) sawHe = true;
            if (id == 1 && offset == 1) sawShe = true;
            if (id == 3 && offset == 2) sawHers = true;
        }
        UT_CHECK(sawHe);
        UT_CHECK(sawShe);
        UT_CHECK(sawHers);
    }

    // --- overlapping occurrences ------------------------------------------------
    {
        const std::vector<std::string> patterns = {"aa", "aaa"};
        AhoCorasick matcher;
        std::string error;
        UT_CHECK(matcher.build(views(patterns), &error));
        const auto hits = collect(matcher, "aaaa");
        // "aa" at 0,1,2 and "aaa" at 0,1 -> 5 hits total.
        UT_CHECK_EQ(hits.size(), static_cast<std::size_t>(5));
    }

    // --- case folding -----------------------------------------------------------
    {
        const std::vector<std::string> patterns = {"cleaner"};
        AhoCorasick matcher;
        std::string error;
        UT_CHECK(matcher.build(views(patterns), &error));
        UT_CHECK_EQ(collect(matcher, "Super CLEANER Pro").size(), static_cast<std::size_t>(1));
        UT_CHECK_EQ(collect(matcher, "supercleanerpro").size(), static_cast<std::size_t>(1));
        UT_CHECK_EQ(collect(matcher, "cleaning").size(), static_cast<std::size_t>(0));
    }

    // --- UTF-8 (Chinese) keywords match byte-exactly ---------------------------
    {
        // 外挂, 破解
        const std::vector<std::string> patterns = {"\xe5\xa4\x96\xe6\x8c\x82", "\xe7\xa0\xb4\xe8\xa7\xa3"};
        AhoCorasick matcher;
        std::string error;
        UT_CHECK(matcher.build(views(patterns), &error));
        // 游戏外挂大师 contains 外挂.
        UT_CHECK_EQ(collect(matcher, "\xe6\xb8\xb8\xe6\x88\x8f\xe5\xa4\x96\xe6\x8c\x82\xe5\xa4\xa7\xe5\xb8\x88").size(),
                    static_cast<std::size_t>(1));
        // 应用名 contains nothing.
        UT_CHECK_EQ(collect(matcher, "\xe5\xba\x94\xe7\x94\xa8\xe5\x90\x8d").size(), static_cast<std::size_t>(0));
    }

    // --- empty automaton is a no-op --------------------------------------------
    {
        AhoCorasick matcher;
        std::string error;
        UT_CHECK(matcher.build({}, &error));
        UT_CHECK(matcher.empty());
        UT_CHECK_EQ(collect(matcher, "anything").size(), static_cast<std::size_t>(0));
    }

    // --- empty pattern is rejected ---------------------------------------------
    {
        const std::vector<std::string> patterns = {"ok", ""};
        AhoCorasick matcher;
        std::string error;
        UT_CHECK(!matcher.build(views(patterns), &error));
        UT_CHECK(!error.empty());
    }

    // --- keyword in the middle of longer text ----------------------------------
    {
        const std::vector<std::string> patterns = {"vpn"};
        AhoCorasick matcher;
        std::string error;
        UT_CHECK(matcher.build(views(patterns), &error));
        const auto hits = collect(matcher, "Free VPN Unlocker");
        UT_CHECK_EQ(hits.size(), static_cast<std::size_t>(1));
        UT_CHECK_EQ(hits[0].first, 0);
    }

    UT_END();
}
