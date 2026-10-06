#include "test_support.h"

#include <string>

#include "unknown_native/permission_index.h"

using unknown::native::PermissionIndex;
using unknown::native::isDangerousPermission;

int main() {
    // --- interning and lookups --------------------------------------------------
    {
        PermissionIndex index;
        index.reserve(8);
        const auto sms = index.intern("android.permission.READ_SMS");
        const auto contacts = index.intern("android.permission.READ_CONTACTS");
        const auto smsAgain = index.intern("android.permission.READ_SMS");

        UT_CHECK_EQ(sms, smsAgain);
        UT_CHECK(sms != contacts);
        UT_CHECK_EQ(index.size(), static_cast<std::uint32_t>(2));
        UT_CHECK_EQ(index.find("android.permission.READ_SMS"), static_cast<std::int32_t>(sms));
        UT_CHECK_EQ(index.find("android.permission.READ_CONTACTS"), static_cast<std::int32_t>(contacts));
        UT_CHECK_EQ(index.find("android.permission.CAMERA"), static_cast<std::int32_t>(-1));
        UT_CHECK_EQ(index.find(""), static_cast<std::int32_t>(-1));
    }

    // --- growth across rehashes ---------------------------------------------------
    {
        PermissionIndex index;
        for (int i = 0; i < 500; ++i) {
            index.intern("permission.number." + std::to_string(i));
        }
        UT_CHECK_EQ(index.size(), static_cast<std::uint32_t>(500));
        bool allFound = true;
        for (int i = 0; i < 500; ++i) {
            if (index.find("permission.number." + std::to_string(i)) != i) {
                allFound = false;
            }
        }
        UT_CHECK(allFound);
    }

    // --- duplicate interning keeps ids stable ------------------------------------
    {
        PermissionIndex index;
        const auto first = index.intern("dup");
        for (int i = 0; i < 20; ++i) {
            UT_CHECK_EQ(index.intern("dup"), first);
        }
        UT_CHECK_EQ(index.size(), static_cast<std::uint32_t>(1));
    }

    // --- dangerous permission table ----------------------------------------------
    UT_CHECK(isDangerousPermission("android.permission.READ_SMS"));
    UT_CHECK(isDangerousPermission("android.permission.SYSTEM_ALERT_WINDOW"));
    UT_CHECK(isDangerousPermission("android.permission.QUERY_ALL_PACKAGES"));
    UT_CHECK(isDangerousPermission("android.permission.REQUEST_INSTALL_PACKAGES"));
    UT_CHECK(isDangerousPermission("android.permission.BIND_ACCESSIBILITY_SERVICE"));
    UT_CHECK(isDangerousPermission("android.permission.ACCESS_BACKGROUND_LOCATION"));
    UT_CHECK(isDangerousPermission("android.permission.READ_MEDIA_VIDEO"));
    UT_CHECK(!isDangerousPermission("android.permission.FOREGROUND_SERVICE"));
    UT_CHECK(!isDangerousPermission("android.permission.INTERNET"));
    UT_CHECK(!isDangerousPermission("com.customapp.PERMISSION"));
    UT_CHECK(!isDangerousPermission(""));
    UT_CHECK(!isDangerousPermission("read_sms"));  // case sensitive by design

    UT_END();
}
