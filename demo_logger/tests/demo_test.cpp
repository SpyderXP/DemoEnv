#include <gtest/gtest.h>
#define __GTEST_DEMO__

extern "C" {
#include "logger.h"
}

TEST(logger, init_logger)
{
    EXPECT_EQ(0, init_logger(NULL, NULL));
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
