# Makefile

# 编译器
CXX = g++
CC = gcc

# 编译器选项
CXXFLAGS = -std=c++11 -I./ -I../inc
CFLAGS = -I./ -I../inc

# 链接器选项
LDFLAGS = -lgtest -lgtest_main -lpthread

# 目标文件目录
OBJ_DIR = obj

# 源文件和目标文件
SRCS	:= $(wildcard ../src/*.c)
OBJS	:= $(patsubst ../src/%.c, obj/%.o, $(SRCS))

# 测试文件
TEST_SRCS = ./demo_test.cpp
TEST_OBJS = $(TEST_SRCS:./%.cpp=$(OBJ_DIR)/%.o)

# 可执行文件
TARGET = test_runner

# 默认目标
all: $(TARGET)

# 编译源文件
$(OBJ_DIR)/%.o: ../src/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# 编译测试文件
$(OBJ_DIR)/%.o: ./%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 链接目标文件生成可执行文件
$(TARGET): $(OBJS) $(TEST_OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# 清理生成的文件
clean:
	$(RM) $(OBJS) $(TEST_OBJS) $(TARGET)

.PHONY: all clean