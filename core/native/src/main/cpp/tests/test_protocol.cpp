#include "test_support.h"

#include <string>

#include "unknown_native/protocol.h"
#include "unknown_native/sha256.h"

using unknown::native::Snapshot;
using unknown::native::isValidSha256Hex;
using namespace unknown::native::protocol;

namespace {

const char* kField = "\x1f";
const char* kList = "\x1e";

bool parses(std::string_view line, Snapshot* out) {
    std::string error;
    return parseSnapshot(line, out, &error);
}

}  // namespace

int main() {
    // --- well-formed snapshot ---------------------------------------------------
    {
        const std::string line = std::string("com.example.app") + kField + "Example App" + kField + "33" + kField +
                                 std::string("android.permission.INTERNET") + kList +
                                 "android.permission.READ_SMS" + kField + "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        Snapshot snapshot;
        UT_CHECK(parses(line, &snapshot));
        UT_CHECK_EQ(snapshot.packageName, std::string_view("com.example.app"));
        UT_CHECK_EQ(snapshot.label, std::string_view("Example App"));
        UT_CHECK_EQ(snapshot.targetSdk, 33);
        UT_CHECK_EQ(snapshot.permissions.size(), static_cast<std::size_t>(2));
        UT_CHECK_EQ(snapshot.permissions[0], std::string_view("android.permission.INTERNET"));
        UT_CHECK_EQ(snapshot.permissions[1], std::string_view("android.permission.READ_SMS"));
        UT_CHECK_EQ(snapshot.sha256Hex.size(), static_cast<std::size_t>(64));
    }

    // --- empty permissions / empty hash ------------------------------------------
    {
        const std::string line = std::string("com.example.app") + kField + "Label" + kField + "26" + kField + "" + kField + "";
        Snapshot snapshot;
        UT_CHECK(parses(line, &snapshot));
        UT_CHECK(snapshot.permissions.empty());
        UT_CHECK(snapshot.sha256Hex.empty());
    }

    // --- trailing newline / CR are tolerated ---------------------------------------
    {
        const std::string line = std::string("com.app") + kField + "L" + kField + "30" + kField + "" + kField + "" + "\r\n";
        Snapshot snapshot;
        UT_CHECK(parses(line, &snapshot));
        UT_CHECK_EQ(snapshot.targetSdk, 30);
    }

    // --- malformed inputs ------------------------------------------------------------
    {
        Snapshot snapshot;
        std::string error;
        UT_CHECK(!parseSnapshot("", &snapshot, &error));
        UT_CHECK(!error.empty());

        error.clear();
        UT_CHECK(!parseSnapshot(std::string("only") + kField + "two", &snapshot, &error));
        UT_CHECK(!error.empty());

        error.clear();
        UT_CHECK(!parseSnapshot(std::string("com.app") + kField + "L" + kField + "abc" + kField + "" + kField + "", &snapshot, &error));
        UT_CHECK(!error.empty());

        error.clear();
        UT_CHECK(!parseSnapshot(std::string("") + kField + "L" + kField + "30" + kField + "" + kField + "", &snapshot, &error));
        UT_CHECK(!error.empty());

        error.clear();
        UT_CHECK(!parseSnapshot(std::string("com.app") + kField + "L" + kField + "30" + kField + "" + kField + "abc", &snapshot, &error));
        UT_CHECK(!error.empty());

        error.clear();
        UT_CHECK(!parseSnapshot(std::string("com.app") + kField + "L" + kField + "30" + kField + "" + kField + "" + kField + "extra",
                                &snapshot, &error));
        UT_CHECK(!error.empty());

        error.clear();
        // A negative targetSdk is odd but parses fine.
        UT_CHECK(parseSnapshot(std::string("com.app") + kField + "L" + kField + "-30" + kField + "" + kField + "", &snapshot, &error));
        UT_CHECK(error.empty());
        UT_CHECK_EQ(snapshot.targetSdk, -30);
    }

    // --- single permission without separator -----------------------------------------
    {
        const std::string line = std::string("com.app") + kField + "L" + kField + "31" + kField + "android.permission.CAMERA" + kField + "";
        Snapshot snapshot;
        UT_CHECK(parses(line, &snapshot));
        UT_CHECK_EQ(snapshot.permissions.size(), static_cast<std::size_t>(1));
    }

    // --- sha256 helper sanity ----------------------------------------------------------
    UT_CHECK(isValidSha256Hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    UT_END();
}
