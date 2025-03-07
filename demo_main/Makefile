# CC				:= arm-linux-gnueabihf-gcc
# CXX				:= arm-linux-gnueabihf-g++
# AR				:= arm-linux-gnueabihf-ar
CC				:= gcc
CXX				:= g++
AR				:= ar
RM				:= rm -rf
CFLAGS			:= -std=gnu99 -Wall -funwind-tables
CXXFLAGS		:= -std=c++11 -Wall -funwind-tables

ifeq ($(RELEASE),0)
	CFLAGS += -g3 -O0
	CXXFLAGS += -g3 -O0
else
	CFLAGS += -g
	CXXFLAGS += -g
endif

TARGETS				:= crypto_tool ffmpeg_tool test_code tool_center sign_tool

CFLAGS	+= -Iinc -I../common_inc

CRYPTO_TOOL_SRCS	:= src/crypto_tool.c
CRYPTO_TOOL_OBJS	:= $(CRYPTO_TOOL_SRCS:src/%.c=obj/%.o)
CRYPTO_TOOL_LDFLAGS += -rdynamic -no-pie -L../thd_lib/x86 -L../demo_crypto/lib/x86 -L../demo_logger/lib/x86 -L../demo_common/lib/x86
CRYPTO_TOOL			:= crypto_tool

FFMPEG_TOOL_SRCS	:= src/ffmpeg_tool.c
FFMPEG_TOOL_OBJS	:= $(FFMPEG_TOOL_SRCS:src/%.c=obj/%.o)
FFMPEG_TOOL_LDFLAGS += -rdynamic -no-pie -L../thd_lib/x86 -L../demo_logger/lib/x86 -L../demo_common/lib/x86
FFMPEG_TOOL			:= ffmpeg_tool

TEST_CODE_SRCS		:= src/common_interface_test.c
TEST_CODE_OBJS		:= $(TEST_CODE_SRCS:src/%.c=obj/%.o)
TEST_CODE_LDFLAGS += -rdynamic -no-pie -L../thd_lib/x86 -L../demo_logger/lib/x86 -L../demo_common/lib/x86
TEST_CODE			:= test_code

TOOL_CENTER_SRCS	:= src/tool_center.c
TOOL_CENTER_OBJS	:= $(TOOL_CENTER_SRCS:src/%.c=obj/%.o)
TOOL_CENTER_LDFLAGS += -rdynamic -no-pie -L../thd_lib/x86 -L../demo_logger/lib/x86 -L../demo_common/lib/x86
TOOL_CENTER			:= tool_center

SIGN_TOOL_SRCS		:= src/sign_tool.c
SIGN_TOOL_OBJS		:= $(SIGN_TOOL_SRCS:src/%.c=obj/%.o)
SIGN_TOOL_LDFLAGS += -rdynamic -no-pie -L../thd_lib/x86 -L../demo_crypto/lib/x86 -L../demo_logger/lib/x86 -L../demo_common/lib/x86
SIGN_TOOL			:= sign_tool

# 添加需要链接的库文件
ifeq ($(LIB_TYPE),dynamic)
	CRYPTO_TOOL_LDLIBS	+= -lcustom_crypto -llogger -lcommon -lcjson -lssl -lcrypto -lm -lpthread -lstdc++
	FFMPEG_TOOL_LDLIBS	+= -llogger -lcommon -lcjson -lm -lpthread -lstdc++
	TEST_CODE_LDLIBS	+= -llogger -lcommon -lcjson -lm -lpthread -lstdc++
	TOOL_CENTER_LDLIBS	+= -llogger -lcommon -lcjson -lm -lreadline -lhistory -lpthread -lstdc++
	SIGN_TOOL_LDLIBS	+= -lcustom_crypto -llogger -lcommon -lcjson -lssl -lcrypto -lm -lpthread -lstdc++
else
	CRYPTO_TOOL_LDLIBS	+= -Wl,-Bstatic -lcustom_crypto -llogger -lcommon -lcjson -Wl,-Bdynamic -lssl -lcrypto -lm -lpthread -lstdc++
	FFMPEG_TOOL_LDLIBS	+= -Wl,-Bstatic -llogger -lcommon -lcjson -Wl,-Bdynamic -lm -lpthread -lstdc++
	TEST_CODE_LDLIBS	+= -Wl,-Bstatic -llogger -lcommon -lcjson -Wl,-Bdynamic -lm -lpthread -lstdc++
	TOOL_CENTER_LDLIBS	+= -Wl,-Bstatic -llogger -lcommon -lcjson -Wl,-Bdynamic -lm -lreadline -lhistory -lpthread -lstdc++
	SIGN_TOOL_LDLIBS	+= -Wl,-Bstatic -lcustom_crypto -llogger -lcommon -lcjson -Wl,-Bdynamic -lssl -lcrypto -lm -lpthread -lstdc++
endif

.PHONY : all clean

default : all

all : $(TARGETS)

obj/%.o : src/%.c
#	@echo "$(CC) $<"
	$(CC) $(CFLAGS) -c -o $@ $<

crypto_tool: $(CRYPTO_TOOL_OBJS)
#	@echo "$(CC) $^"
	$(CC) -o $@ $^ $(CRYPTO_TOOL_LDFLAGS) $(CRYPTO_TOOL_LDLIBS)

ffmpeg_tool: $(FFMPEG_TOOL_OBJS)
#	@echo "$(CC) $^"
	$(CC) -o $@ $^ $(FFMPEG_TOOL_LDFLAGS) $(FFMPEG_TOOL_LDLIBS)

test_code: $(TEST_CODE_OBJS)
#	@echo "$(CC) $^"
	$(CC) -o $@ $^ $(TEST_CODE_LDFLAGS) $(TEST_CODE_LDLIBS)

tool_center: $(TOOL_CENTER_OBJS)
#	@echo "$(CC) $^"
	$(CC) -o $@ $^ $(TOOL_CENTER_LDFLAGS) $(TOOL_CENTER_LDLIBS)

sign_tool: $(SIGN_TOOL_OBJS)
#	@echo "$(CC) $^"
	$(CC) -o $@ $^ $(SIGN_TOOL_LDFLAGS) $(SIGN_TOOL_LDLIBS)

clean :
	@$(RM) $(CRYPTO_TOOL_OBJS) $(FFMPEG_TOOL_OBJS) $(TEST_CODE_OBJS) $(TOOL_CENTER_OBJS) $(SIGN_TOOL_OBJS) $(CRYPTO_TOOL) $(FFMPEG_TOOL) $(TEST_CODE) $(TOOL_CENTER) $(SIGN_TOOL)
