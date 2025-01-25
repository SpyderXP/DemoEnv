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

TARGETS				:= crypto_tool ffmpeg_tool

CFLAGS	+= -Iinc -I../common_inc

CRYPTO_TOOL_SRCS	:= src/crypto_tool.c
CRYPTO_TOOL_OBJS 	:= $(CRYPTO_TOOL_SRCS:src/%.c=obj/%.o)
CRYPTO_TOOL_LDFLAGS += -rdynamic -no-pie -L../thd_lib/x86 -L../demo_crypto/lib/x86 -L../demo_logger/lib/x86 -L../demo_common/lib/x86
CRYPTO_TOOL			:= crypto_tool

FFMPEG_TOOL_SRCS	:= src/ffmpeg_tool.c
FFMPEG_TOOL_OBJS 	:= $(FFMPEG_TOOL_SRCS:src/%.c=obj/%.o)
FFMPEG_TOOL_LDFLAGS += -rdynamic -no-pie -L../thd_lib/x86 -L../demo_logger/lib/x86 -L../demo_common/lib/x86
FFMPEG_TOOL			:= ffmpeg_tool

# 添加需要链接的库文件
ifeq ($(LIB_TYPE),dynamic)
	CRYPTO_TOOL_LDLIBS	+= -lcustom_crypto -llogger -lcommon -lcjson -lssl -lcrypto -lm -lpthread -lstdc++
	FFMPEG_TOOL_LDLIBS	+= -llogger -lcommon -lcjson -lm -lpthread -lstdc++
else
	CRYPTO_TOOL_LDLIBS	+= -Wl,-Bstatic -lcustom_crypto -llogger -lcommon -lcjson -Wl,-Bdynamic -lssl -lcrypto -lm -lpthread -lstdc++
	FFMPEG_TOOL_LDLIBS	+= -Wl,-Bstatic -llogger -lcommon -lcjson -Wl,-Bdynamic -lm -lpthread -lstdc++
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

clean :
	@$(RM) $(CRYPTO_TOOL_OBJS) $(FFMPEG_TOOL_OBJS) $(CRYPTO_TOOL) $(FFMPEG_TOOL)
