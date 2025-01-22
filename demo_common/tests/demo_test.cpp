#include <gtest/gtest.h>
#define __GTEST_DEMO__

extern "C" {
#include "common_macro.h"
}

TEST(common, fast_strncat)
{
    char *tmp = NULL;
    char *str0 = NULL;
    char str1[32] = "hello";
    char str2[32] = "world";

    str0 = (char *)calloc(1, 64);
    tmp = str0;

    tmp = fast_strncat(tmp, str1, strlen(str1));
    tmp = fast_strncat(tmp, str2, strlen(str2));
    EXPECT_STREQ(str0, "helloworld");
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
