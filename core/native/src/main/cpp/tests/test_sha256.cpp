#include "test_support.h"

#include <string>

#include "unknown_native/sha256.h"

using unknown::native::Sha256;
using unknown::native::isValidSha256Hex;
using unknown::native::normalizeSha256Hex;
using unknown::native::toHexLower;

namespace {

std::string digestHex(const std::string& message) {
    Sha256 hasher;
    hasher.update(message.data(), message.size());
    std::uint8_t digest[32];
    hasher.finish(digest);
    return toHexLower(digest, 32);
}

}  // namespace

int main() {
    // --- FIPS 180-4 / NIST vectors ---------------------------------------------
    UT_CHECK_EQ(digestHex(""),
                std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    UT_CHECK_EQ(digestHex("abc"),
                std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    UT_CHECK_EQ(digestHex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    // --- one million 'a' fed in chunks -----------------------------------------
    {
        Sha256 hasher;
        const std::string chunk(1000, 'a');
        for (int i = 0; i < 1000; ++i) {
            hasher.update(chunk.data(), chunk.size());
        }
        std::uint8_t digest[32];
        hasher.finish(digest);
        UT_CHECK_EQ(toHexLower(digest, 32),
                    std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }

    // --- chunked updates equal a single update ---------------------------------
    {
        const std::string message = "The quick brown fox jumps over the lazy dog";
        const std::string single = digestHex(message);

        Sha256 hasher;
        for (std::size_t i = 0; i < message.size(); i += 7) {
            const std::size_t take = std::min<std::size_t>(7, message.size() - i);
            hasher.update(message.data() + i, take);
        }
        std::uint8_t digest[32];
        hasher.finish(digest);
        UT_CHECK_EQ(toHexLower(digest, 32), single);
    }

    // --- reuse after finish() --------------------------------------------------
    {
        Sha256 hasher;
        std::uint8_t digest[32];
        hasher.update("abc", 3);
        hasher.finish(digest);
        hasher.update("abc", 3);
        hasher.finish(digest);
        UT_CHECK_EQ(toHexLower(digest, 32),
                    std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    // --- helpers ----------------------------------------------------------------
    UT_CHECK(isValidSha256Hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    UT_CHECK(isValidSha256Hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"));
    UT_CHECK(!isValidSha256Hex(""));
    UT_CHECK(!isValidSha256Hex("abc"));
    UT_CHECK(!isValidSha256Hex(std::string(65, 'a')));
    UT_CHECK(!isValidSha256Hex(std::string(64, 'g')));

    {
        char buffer[64];
        UT_CHECK(normalizeSha256Hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", buffer));
        UT_CHECK_EQ(std::string(buffer, 64),
                    std::string("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        UT_CHECK(!normalizeSha256Hex("short", buffer));
    }

    UT_END();
}
