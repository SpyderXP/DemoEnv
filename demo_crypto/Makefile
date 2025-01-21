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

# LIB_DIR		:= lib/arm
LIB_DIR		:= lib/x86
STATIC_LIB	:= $(LIB_DIR)/libcustom_crypto.a
SHARED_LIB	:= $(LIB_DIR)/libcustom_crypto.so

# 添加需要搜索的头文件路径
CFLAGS	+= -Iinc -I../demo_logger/inc -fPIC

# 添加需要链接的库文件
LDLIBS	+= -lssl -lcrypto -lstdc++

.PHONY : all build clean

default : all

all : build

build : $(STATIC_LIB) $(SHARED_LIB)

obj/%.o : src/%.c $(DEPS)
#	@echo "$(CC) $<"
	$(CC) $(CFLAGS) -c -o $@ $<

$(STATIC_LIB) : $(OBJS) | $(LIB_DIR)
#	@echo "$(AR) $@"
	$(AR) rcs $@ $^

$(SHARED_LIB) : $(OBJS) | $(LIB_DIR)
#	@echo "$(CC) $@"
	$(CC) -shared -o $@ $^ $(LDLIBS)

clean :
	$(RM) $(OBJS) $(STATIC_LIB) $(SHARED_LIB)
