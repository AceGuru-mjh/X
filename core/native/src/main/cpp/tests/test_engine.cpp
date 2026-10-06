#include "test_support.h"

#include <deque>
#include <string>
#include <vector>

#include "unknown_native/engine.h"
#include "unknown_native/protocol.h"

using unknown::native::CompiledRuleSet;
using unknown::native::EvalScratch;
using unknown::native::RuleType;
using unknown::native::Severity;
using unknown::native::Snapshot;
using unknown::native::Verdict;
using unknown::native::VerdictLevel;
using namespace unknown::native::protocol;

namespace {

const char* kField = "\x1f";
const char* kList = "\x1e";

const char* kPackageHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

std::string rule(const std::string& type, const std::string& id, const std::string& name, int severity) {
    return type + kField + id + kField + name + kField + std::to_string(severity);
}

/** Builds a full rule blob for the classic repackaged-malware scenario. */
std::string defaultRulesBlob() {
    std::vector<std::string> lines;

    // exact package rule, medium
    lines.push_back(rule("P", "pkg.loan.shark", "贷款鲨鱼包名", 1) + kField + "com.loan.shark" + kField + "0");
    // regex package rule, high
    lines.push_back(rule("P", "pkg.regex.miner", "挖矿包名正则", 2) + kField + "^com\\.(aaa|bbb)\\.miner\\..*" + kField + "1");
    // keyword rule, high: 外挂 / 破解
    lines.push_back(rule("K", "kw.cracked", "破解关键词", 2) + kField +
                    (std::string("\xe7\xa0\xb4\xe8\xa7\xa3") + kList + "\xe5\xa4\x96\xe6\x8c\x82"));
    // permission combo rule, critical: SMS + CONTACTS + at least one of (SMS,BODY_SENSORS,SYSTEM_ALERT_WINDOW)
    lines.push_back(rule("C", "combo.repack", "重打包权限组合", 3) + kField +
                    (std::string("android.permission.READ_SMS") + kList + "android.permission.READ_CONTACTS") + kField +
                    (std::string("android.permission.RECEIVE_SMS") + kList + "android.permission.SYSTEM_ALERT_WINDOW" + kList +
                     "android.permission.BODY_SENSORS") +
                    kField + "1");
    // apk hash rule, critical
    lines.push_back(rule("H", "hash.known.bad", "已知恶意样本", 3) + kField + kPackageHash);
    // target sdk rule, medium
    lines.push_back(rule("T", "sdk.evasive", "低targetSdk规避", 1) + kField + "22" + kField + "1");

    std::string blob;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i > 0) {
            blob.push_back('\n');
        }
        blob += lines[i];
    }
    return blob;
}

/** Stable storage: snapshot views must outlive the evaluate() call. */
std::deque<std::string>& snapshotStorage() {
    static std::deque<std::string> storage;
    return storage;
}

Snapshot makeSnapshot(const std::string& packageName,
                      const std::string& label,
                      int targetSdk,
                      const std::vector<std::string>& permissions,
                      const std::string& sha256 = "") {
    std::string perms;
    for (std::size_t i = 0; i < permissions.size(); ++i) {
        if (i > 0) {
            perms += kList;
        }
        perms += permissions[i];
    }
    std::string line = packageName + kField + label + kField + std::to_string(targetSdk) + kField + perms + kField + sha256;
    snapshotStorage().push_back(std::move(line));
    Snapshot snapshot;
    std::string error;
    if (!parseSnapshot(snapshotStorage().back(), &snapshot, &error)) {
        return Snapshot{};
    }
    return snapshot;
}

Verdict evaluateAll(const CompiledRuleSet& set, const Snapshot& snapshot) {
    // Mirrors the JNI bridge: one persistent scratch keeps Verdict::matches
    // valid after the call returns (single-threaded test binary).
    static EvalScratch scratch;
    Verdict verdict;
    set.evaluate(snapshot, scratch, verdict);
    return verdict;
}

}  // namespace

int main() {
    // --- compile -----------------------------------------------------------------
    std::string error;
    auto set = CompiledRuleSet::compile(defaultRulesBlob(), &error);
    UT_CHECK(set != nullptr);
    if (set == nullptr) {
        std::fprintf(stderr, "compile error: %s\n", error.c_str());
        UT_END();
    }
    UT_CHECK_EQ(set->ruleCount(), static_cast<std::size_t>(6));
    UT_CHECK_EQ(set->permissionCount(), static_cast<std::size_t>(5));

    // --- clean package -------------------------------------------------------------
    {
        const Snapshot snapshot = makeSnapshot("com.google.android.gm", "Gmail", 34,
                                               {"android.permission.INTERNET", "android.permission.FOREGROUND_SERVICE"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.score, 0);
        UT_CHECK(verdict.level == VerdictLevel::Clean);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(0));
    }

    // --- exact package hit (medium = 25 -> suspicious) --------------------------------
    {
        const Snapshot snapshot = makeSnapshot("com.loan.shark", "快速借钱", 30, {"android.permission.INTERNET"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.score, 25);
        UT_CHECK(verdict.level == VerdictLevel::Suspicious);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(1));
        UT_CHECK_EQ(verdict.matches[0].ruleId, std::string_view("pkg.loan.shark"));
        UT_CHECK(verdict.matches[0].severity == Severity::Medium);
    }

    // --- regex package hit (high = 50 -> dangerous) -----------------------------------
    {
        const Snapshot snapshot = makeSnapshot("com.aaa.miner.free", "Miner", 33, {"android.permission.INTERNET"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.score, 50);
        UT_CHECK(verdict.level == VerdictLevel::Dangerous);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(1));
        UT_CHECK_EQ(verdict.matches[0].ruleId, std::string_view("pkg.regex.miner"));
    }

    // --- keyword hit with Chinese label (high) -----------------------------------------
    {
        const std::string label = "\xe6\xb8\xb8\xe6\x88\x8f\xe5\xa4\x96\xe6\x8c\x82\xe5\xa4\xa7\xe5\xb8\x88";  // 游戏外挂大师
        const Snapshot snapshot = makeSnapshot("com.game.helper", label, 33, {"android.permission.INTERNET"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(1));
        UT_CHECK_EQ(verdict.matches[0].ruleId, std::string_view("kw.cracked"));
        UT_CHECK_EQ(verdict.score, 50);
    }

    // --- permission combo: required all + anyOf count (critical = 100) ------------------
    {
        const Snapshot snapshot = makeSnapshot(
            "com.unknown.repacked", "Fancy App", 33,
            {"android.permission.READ_SMS", "android.permission.READ_CONTACTS", "android.permission.SYSTEM_ALERT_WINDOW"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(1));
        UT_CHECK_EQ(verdict.matches[0].ruleId, std::string_view("combo.repack"));
        UT_CHECK_EQ(verdict.score, 100);
        UT_CHECK(verdict.level == VerdictLevel::Dangerous);
    }

    // --- permission combo: missing a required permission -> no match --------------------
    {
        const Snapshot snapshot = makeSnapshot(
            "com.unknown.repacked", "Fancy App", 33,
            {"android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(0));
    }

    // --- permission combo: required ok but anyOf count unmet -> no match -----------------
    {
        const Snapshot snapshot = makeSnapshot(
            "com.unknown.repacked", "Fancy App", 33,
            {"android.permission.READ_SMS", "android.permission.READ_CONTACTS"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(0));
    }

    // --- hash hit, case-insensitive snapshot hash (critical) -----------------------------
    {
        const std::string upperHash = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        const Snapshot snapshot = makeSnapshot("com.unknown.bad", "Bad", 33, {"android.permission.INTERNET"}, upperHash);
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(1));
        UT_CHECK_EQ(verdict.matches[0].ruleId, std::string_view("hash.known.bad"));
    }

    // --- targetSdk rule: low sdk + dangerous permission (medium) --------------------------
    {
        const Snapshot snapshot = makeSnapshot("com.old.app", "Old", 17, {"android.permission.READ_SMS"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(1));
        UT_CHECK_EQ(verdict.matches[0].ruleId, std::string_view("sdk.evasive"));
    }

    // --- targetSdk rule: low sdk but no dangerous permission -> no match -------------------
    {
        const Snapshot snapshot = makeSnapshot("com.old.app", "Old", 17, {"android.permission.INTERNET"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(0));
    }

    // --- targetSdk rule: high sdk -> no match ----------------------------------------------
    {
        const Snapshot snapshot = makeSnapshot("com.new.app", "New", 34, {"android.permission.READ_SMS"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(0));
    }

    // --- multiple matches: severity-descending order, scores sum up -------------------------
    {
        const std::string label = "\xe7\xa0\xb4\xe8\xa7\xa3\xe7\x89\x88\xe5\xba\x94\xe7\x94\xa8";  // 破解版应用
        const Snapshot snapshot = makeSnapshot("com.loan.shark", label, 17,
                                               {"android.permission.READ_SMS", "android.permission.READ_CONTACTS",
                                                "android.permission.SYSTEM_ALERT_WINDOW"});
        const Verdict verdict = evaluateAll(*set, snapshot);
        // exact package (medium 25) + keywords (high 50) + combo (critical 100) + targetSdk (medium 25) = 200
        UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(4));
        UT_CHECK_EQ(verdict.score, 200);
        UT_CHECK(verdict.level == VerdictLevel::Dangerous);
        UT_CHECK(verdict.matches[0].severity == Severity::Critical);
        UT_CHECK(verdict.matches[1].severity == Severity::High);
        UT_CHECK(verdict.matches[2].severity == Severity::Medium);
        UT_CHECK(verdict.matches[3].severity == Severity::Medium);
        // detail strings are non-empty for every match
        UT_CHECK(verdict.matches[0].detailLength > 0);
        UT_CHECK(verdict.matches[1].detailLength > 0);
        UT_CHECK(verdict.matches[2].detailLength > 0);
        UT_CHECK(verdict.matches[3].detailLength > 0);
    }

    // --- scratch reuse produces identical results (steady state) -----------------------------
    {
        EvalScratch scratch;
        Verdict first;
        Verdict second;
        const Snapshot snapshot = makeSnapshot("com.loan.shark", "\xe7\xa0\xb4\xe8\xa7\xa3", 30, {"android.permission.INTERNET"});
        set->evaluate(snapshot, scratch, first);
        const std::string firstId{first.matches[0].ruleId};
        const int firstScore = first.score;
        set->evaluate(makeSnapshot("com.other", "Other", 34, {}), scratch, second);
        UT_CHECK_EQ(second.score, 0);
        set->evaluate(snapshot, scratch, first);
        UT_CHECK_EQ(first.score, firstScore);
        UT_CHECK_EQ(std::string{first.matches[0].ruleId}, firstId);
    }

    // --- empty rule blob compiles into a clean engine -----------------------------------------
    {
        std::string emptyError;
        auto emptySet = CompiledRuleSet::compile("", &emptyError);
        UT_CHECK(emptySet != nullptr);
        UT_CHECK_EQ(emptySet->ruleCount(), static_cast<std::size_t>(0));
        const Snapshot snapshot = makeSnapshot("com.anything", "Any", 30, {"android.permission.READ_SMS"});
        const Verdict verdict = evaluateAll(*emptySet, snapshot);
        UT_CHECK_EQ(verdict.score, 0);
        UT_CHECK(verdict.level == VerdictLevel::Clean);
    }

    // --- compile errors surface with the offending line/rule ----------------------------------
    {
        std::string err;
        auto bad = CompiledRuleSet::compile(std::string("X") + kField + "id" + kField + "name" + kField + "0", &err);
        UT_CHECK(bad == nullptr);
        UT_CHECK(!err.empty());

        err.clear();
        bad = CompiledRuleSet::compile(std::string("P") + kField + "" + kField + "name" + kField + "0" + kField + "com.a" + kField + "0", &err);
        UT_CHECK(bad == nullptr);
        UT_CHECK(!err.empty());

        err.clear();
        bad = CompiledRuleSet::compile(std::string("P") + kField + "id" + kField + "name" + kField + "9" + kField + "com.a" + kField + "0", &err);
        UT_CHECK(bad == nullptr);
        UT_CHECK(!err.empty());

        err.clear();
        bad = CompiledRuleSet::compile(std::string("P") + kField + "id" + kField + "name" + kField + "0" + kField + "^com(" + kField + "1", &err);
        UT_CHECK(bad == nullptr);
        UT_CHECK(!err.empty());

        err.clear();
        bad = CompiledRuleSet::compile(std::string("H") + kField + "id" + kField + "name" + kField + "0" + kField + "abc", &err);
        UT_CHECK(bad == nullptr);
        UT_CHECK(!err.empty());
    }

    // --- duplicate exact package entries: both rules match -------------------------------------
    {
        const std::string blob = std::string("P") + kField + "first" + kField + "First" + kField + "1" + kField + "com.dup" + kField + "0" +
                                 "\n" + std::string("P") + kField + "second" + kField + "Second" + kField + "2" + kField + "com.dup" + kField + "0";
        std::string err;
        auto dupSet = CompiledRuleSet::compile(blob, &err);
        UT_CHECK(dupSet != nullptr);
        if (dupSet != nullptr) {
            const Snapshot snapshot = makeSnapshot("com.dup", "Dup", 30, {});
            const Verdict verdict = evaluateAll(*dupSet, snapshot);
            UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(2));
            UT_CHECK_EQ(verdict.score, 75);  // medium 25 + high 50
        }
    }

    // --- case-variant keywords merge into one folded pattern, both rules hit ------------------
    {
        const std::string blob =
            std::string("K") + kField + "kw.upper" + kField + "Upper" + kField + "0" + kField + "VPN" +
            "\n" + std::string("K") + kField + "kw.lower" + kField + "Lower" + kField + "2" + kField + "vpn";
        std::string err;
        auto caseSet = CompiledRuleSet::compile(blob, &err);
        UT_CHECK(caseSet != nullptr);
        if (caseSet != nullptr) {
            const Snapshot snapshot = makeSnapshot("com.vpn.tool", "Free VPN Tool", 33, {});
            const Verdict verdict = evaluateAll(*caseSet, snapshot);
            UT_CHECK_EQ(verdict.matchCount, static_cast<std::uint32_t>(2));
            UT_CHECK_EQ(verdict.score, 60);  // LOW 10 + HIGH 50
            UT_CHECK(verdict.matches[0].severity == Severity::High);
            UT_CHECK(verdict.matches[1].severity == Severity::Low);
        }
    }

    UT_END();
}
