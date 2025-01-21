#include <gtest/gtest.h>
#define __GTEST_DEMO__

extern "C" {
#include "crypto_custom.h"
}

TEST(crypto_custom, crypto_check_required_param)
{
    EXPECT_EQ(-1, crypto_check_required_param());
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
