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
STATIC_LIB	:= $(LIB_DIR)/libcommon.a
SHARED_LIB	:= $(LIB_DIR)/libcommon.so

# 添加需要搜索的头文件路径
CFLAGS	+= -Iinc -I../common_inc -fPIC

# 添加需要搜索的库文件目录及链接选项
LDFLAGS += -L../thd_lib/x86

# 添加需要链接的库文件
ifeq ($(LIB_TYPE),dynamic)
	LDLIBS	+= -lm -lpthread -lstdc++
else
	LDLIBS	+= -lm -lpthread -lstdc++
endif

.PHONY : all clean

default : all

all : $(STATIC_LIB) $(SHARED_LIB)

obj/%.o : src/%.c $(DEPS)
#	@echo "$(CC) $<"
	$(CC) $(CFLAGS) -c -o $@ $<

$(STATIC_LIB) : $(OBJS) | $(LIB_DIR)
#	@echo "$(AR) $@"
	$(AR) rcs $@ $^

$(SHARED_LIB) : $(OBJS) | $(LIB_DIR)
#	@echo "$(CC) $@"
	$(CC) -shared -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean :
	$(RM) $(OBJS) $(STATIC_LIB) $(SHARED_LIB)
