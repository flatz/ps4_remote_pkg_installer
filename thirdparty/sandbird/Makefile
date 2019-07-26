WINE = wine
WINE_PATH_TOOL = winepath

CC = $(WINE) orbis-clang
AR = $(WINE) orbis-ar

OBJDIR = obj
BLDDIR = build
SRCDIR = src

TARGET = sandbird

C_SRCS = $(wildcard $(SRCDIR)/*.c)

COMMON_FLAGS = -Wall
COMMON_FLAGS += -fdiagnostics-color=always -nostdinc
COMMON_FLAGS += -I $(SCE_ORBIS_SDK_DIR)/host_tools/lib/clang/include -I $(TAUON_SDK_DIR)/include -I $(SCE_ORBIS_SDK_DIR)/target/include -I $(SCE_ORBIS_SDK_DIR)/target/include/common
COMMON_FLAGS += -DNDEBUG -D__BSD_VISIBLE
COMMON_FLAGS += -g

CFLAGS = $(COMMON_FLAGS)
CFLAGS += -std=c11
CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused-label -Werror=implicit-function-declaration
CFLAGS += -fno-strict-aliasing
CFLAGS += -fPIC
CFLAGS += -O3

OBJS = $(addprefix $(OBJDIR)/, $(C_SRCS:.c=.c.o))

.PHONY: all clean

all: post-build

pre-build:
	@mkdir -p $(OBJDIR) $(BLDDIR)

post-build: main-build

main-build: pre-build
	@$(MAKE) --no-print-directory lib

lib: pre-build $(OBJS)
	$(AR) rc $(BLDDIR)/lib$(TARGET).a $(OBJS)

$(OBJDIR)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJDIR) $(BLDDIR)
