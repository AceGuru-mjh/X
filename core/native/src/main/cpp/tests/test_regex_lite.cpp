#include "test_support.h"

#include <string>

#include "unknown_native/regex_lite.h"

using unknown::native::RegexLite;

namespace {

bool matches(std::string_view pattern, std::string_view text) {
    RegexLite regex;
    std::string error;
    if (!RegexLite::compile(pattern, &regex, &error)) {
        return false;
    }
    return regex.search(text);
}

bool compiles(std::string_view pattern) {
    RegexLite regex;
    std::string error;
    return RegexLite::compile(pattern, &regex, &error);
}

}  // namespace

int main() {
    // --- literals and dot -------------------------------------------------------
    UT_CHECK(matches("com.example", "com.example.app"));
    UT_CHECK(!matches("com.example.app", "com.example"));
    UT_CHECK(matches("app", "com.example.app"));
    UT_CHECK(matches("c.m.ex.mple", "com.example.app"));
    UT_CHECK(!matches("c\\.m", "cxm"));  // an escaped dot must not match 'x'

    // --- anchors ----------------------------------------------------------------
    UT_CHECK(matches("^com$", "com"));
    UT_CHECK(!matches("^com$", "com.example"));
    UT_CHECK(!matches("^example", "com.example"));
    UT_CHECK(matches("^com", "com.example"));
    UT_CHECK(matches("app$", "com.example.app"));
    UT_CHECK(!matches("app$", "com.example.appx"));

    // --- star / plus / question --------------------------------------------------
    UT_CHECK(matches("ab*c", "ac"));
    UT_CHECK(matches("ab*c", "abbbbc"));
    UT_CHECK(!matches("ab+c", "ac"));
    UT_CHECK(matches("ab+c", "abc"));
    UT_CHECK(matches("colou?r", "color"));
    UT_CHECK(matches("colou?r", "colour"));
    UT_CHECK(!matches("colou?r", "colouur"));

    // --- alternation -------------------------------------------------------------
    UT_CHECK(matches("foo|bar|baz", "xbary"));
    UT_CHECK(!matches("foo|bar|baz", "qux"));
    UT_CHECK(matches("a|", ""));
    UT_CHECK(matches("^(com|org)\\.example\\..*", "org.example.portal"));
    UT_CHECK(!matches("^(com|org)\\.example\\..*", "net.example.portal"));

    // --- groups ------------------------------------------------------------------
    UT_CHECK(matches("(ab)+", "ababab"));
    UT_CHECK(!matches("(ab)+", "aa"));
    UT_CHECK(matches("(a|b)*c", "abbac"));

    // --- character classes -------------------------------------------------------
    UT_CHECK(matches("[abc]+", "abcabc"));
    UT_CHECK(!matches("^[abc]+$", "abd"));  // unanchored "[abc]+" would still find "ab"
    UT_CHECK(matches("[a-z]+\\.[0-9]+", "abc.123"));
    UT_CHECK(!matches("[a-z]+\\.[0-9]+", "abc.xy"));
    UT_CHECK(matches("[^0-9]+", "abc"));
    UT_CHECK(!matches("^[^0-9]+$", "ab1"));
    UT_CHECK(matches("[]]", "]"));
    UT_CHECK(matches("[a-]", "-"));
    UT_CHECK(matches("[a-cx]", "x"));

    // --- escapes -----------------------------------------------------------------
    UT_CHECK(matches("\\d{3}-\\d{4}", "call 555-1234 now"));
    UT_CHECK(!matches("\\d{3}-\\d{4}", "5551234"));
    UT_CHECK(matches("\\w+@\\w+\\.com", "mail me a@b.com"));
    UT_CHECK(matches("a\\sb", "a b"));
    UT_CHECK(matches("a\\sb", "a\tb"));
    UT_CHECK(matches("a\\.b", "a.b"));
    UT_CHECK(!matches("a\\.b", "axb"));
    UT_CHECK(matches("\\D+", "abc"));

    // --- bounded repetition --------------------------------------------------------
    UT_CHECK(matches("^a{3}$", "aaa"));
    UT_CHECK(!matches("^a{3}$", "aa"));
    UT_CHECK(matches("^a{2,4}$", "aaa"));
    UT_CHECK(!matches("^a{2,4}$", "a"));
    UT_CHECK(!matches("^a{2,4}$", "aaaaa"));
    UT_CHECK(matches("^a{2,}$", "aaaaaa"));
    UT_CHECK(matches("^(ab){2,3}$", "ababab"));
    UT_CHECK(!matches("^(ab){2,3}$", "ab"));
    UT_CHECK(matches("^a{0,2}$", ""));
    UT_CHECK(matches("^a{0}b$", "b"));

    // --- package-name style patterns ---------------------------------------------
    UT_CHECK(matches("^com\\.bad\\..*", "com.bad.payload"));
    UT_CHECK(!matches("^com\\.bad\\..*", "com.good.app"));
    UT_CHECK(matches("loan", "com.loan.shark"));
    UT_CHECK(matches("^(com|cn)\\..*cleaner.*$", "cn.free.cleanerpro"));

    // --- compile errors ------------------------------------------------------------
    UT_CHECK(!compiles(""));
    UT_CHECK(!compiles("(unclosed"));
    UT_CHECK(!compiles("unmatched)"));
    UT_CHECK(!compiles("[unclosed"));
    UT_CHECK(!compiles("a\\"));
    UT_CHECK(!compiles("*abc"));
    UT_CHECK(!compiles("a{3,1}"));
    UT_CHECK(!compiles("a{999}"));
    UT_CHECK(!compiles("a{"));
    // A '{' at atom position is a literal brace, so "{3}x" compiles and
    // matches the literal text "{3}x".
    UT_CHECK(compiles("{3}x"));
    UT_CHECK(matches("{3}x", "prefix{3}x"));

    // --- pathological pattern cannot hang, recursion is depth-capped -----
    UT_CHECK(!matches("(a*)*b", std::string(120, 'a')));
    UT_CHECK(matches("(a|a)*b", std::string(120, 'a') + "b"));
    // Empty-body loops match the empty string (so search is true), but the
    // depth cap keeps them from blowing the stack or hanging.
    UT_CHECK(matches("(|)*", "com.example.app"));
    UT_CHECK(matches("(){2,}", "com.example.app"));
    UT_CHECK(matches("(a?)*", std::string(120, 'a') + 'x'));

    // --- instruction-budget boundary must fail cleanly, never corrupt ----
    {
        // 20 * "a{100}" (101 instructions each) + "a{25}" (26) = 2046
        // instructions: two slots below the 2048 budget, so each suffix
        // below lands exactly on a different boundary write site.
        std::string base;
        for (int i = 0; i < 20; ++i) {
            base += "a{100}";
        }
        base += "a{25}";
        UT_CHECK(!compiles(base + "a+"));      // '+' loop split site
        UT_CHECK(!compiles(base + "a{1,}"));   // open-ended star site
        UT_CHECK(!compiles(base + "a{1,2}"));  // optional-split site
        UT_CHECK(!compiles(base + "a|"));      // alternation jump site
        UT_CHECK(!compiles(base + "z()"));     // nested group split site
        UT_CHECK(!compiles(base + "a{25}"));   // plain copy overflow
    }

    // --- regex must not match an empty compiled program ------------------------------
    {
        RegexLite regex;
        UT_CHECK(!regex.search("anything"));
    }

    UT_END();
}
