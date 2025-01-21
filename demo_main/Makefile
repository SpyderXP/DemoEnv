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

SRCS	:= $(wildcard src/*.c)
OBJS	:= $(patsubst src/%.c, obj/%.o, $(SRCS))
DEPS	:= $(wildcard inc/*.h)

TARGET		:= crypto_tool

# 添加需要搜索的头文件路径
CFLAGS	+= -Iinc -I../demo_logger/inc -I../demo_crypto/inc

# 添加需要搜索的库文件目录及链接选项
LDFLAGS += -rdynamic -no-pie -L../demo_crypto/lib/x86 -L../demo_logger/lib/x86

# 添加需要链接的库文件
LDLIBS	+= -Wl,-Bstatic -lcustom_crypto -llogger -Wl,-Bdynamic -lssl -lcrypto -lm -lpthread -lstdc++

.PHONY : all build clean

default : all

all : build

build : $(TARGET)

obj/%.o : src/%.c $(DEPS)
#	@echo "$(CC) $<"
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET) : $(OBJS)
#	@echo "$(CC) $^"
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS) 

clean :
	@$(RM) $(OBJS) $(TARGET)
