WINE = wine
WINE_PATH_TOOL = winepath

CC = $(WINE) orbis-clang
CXX = $(WINE) orbis-clang++
LD = $(WINE) orbis-ld
OBJCOPY = $(WINE) orbis-objcopy
PUBCMD = $(WINE) orbis-pub-cmd
MAKE_FSELF = ./make_fself

OBJDIR = obj
BLDDIR = build
MODDIR = sce_module

TARGET = remote_pkg_installer

LIBS = -lkernel_tau_stub_weak -lScePosix_stub_weak -lSceSysmodule_tau_stub_weak -lSceSystemService_stub_weak -lSceSystemService_tau_stub_weak -lSceUserService_stub_weak -lSceUserService_tau_stub_weak -lSceNetCtl_stub_weak -lSceNet_stub_weak -lSceHttp_stub_weak -lSceSsl_stub_weak -lSceAppInstUtil_tau_stub_weak -lSceBgft_tau_stub_weak -lSceNpCommon_tau_stub_weak -lkernel_util
LIBS += -lsandbird -ltiny_json

SDK_MODULES =
EXTRA_MODULES =

AUTH_INFO = 000000000000000000000000001C004000FF000000000080000000000000000000000000000000000000008000400040000000000000008000000000000000080040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

ASM_SRCS = syscalls.S
C_SRCS = http.c installer.c main.c net.c pkg.c server.c sfo.c util.c

COMMON_FLAGS = -Wall
COMMON_FLAGS += -fdiagnostics-color=always
COMMON_FLAGS += -I $(TAUON_SDK_DIR)/include -I $(SCE_ORBIS_SDK_DIR)/target/include -I $(SCE_ORBIS_SDK_DIR)/target/include/common -I thirdparty/sandbird/src -I thirdparty/tiny-json -I thirdparty/uthash
COMMON_FLAGS += -DNDEBUG
#COMMON_FLAGS += -g

CFLAGS = $(COMMON_FLAGS)
CFLAGS += -std=c11
CFLAGS += -Wno-unused-function -Wno-unused-label -Werror=implicit-function-declaration
CFLAGS += -fno-strict-aliasing
CFLAGS += -fPIC
CFLAGS += -O3

ASFLAGS = $(COMMON_FLAGS)

LDFLAGS = -s -Wl,--strip-unused-data
LDFLAGS += -L $(TAUON_SDK_DIR)/lib -L $(SCE_ORBIS_SDK_DIR)/target/lib -L thirdparty/sandbird/build -L thirdparty/tiny-json/build

OBJS = $(addprefix $(OBJDIR)/,$(ASM_SRCS:.S=.S.o) $(C_SRCS:.c=.c.o))

.PHONY: all clean

all: post-build

pre-build:
	@mkdir -p $(MODDIR) $(OBJDIR) $(BLDDIR)
	#@for filename in $(SDK_MODULES); do \
	#	if [ ! -f "$(MODDIR)/$$filename" ]; then \
	#		echo Copying $$filename...; \
	#		cp "`$(WINE_PATH_TOOL) -u \"$(SCE_ORBIS_SDK_DIR)/target/sce_module/$$filename\"`" $(MODDIR)/; \
	#	fi; \
	#done;
	#@for filename in $(EXTRA_MODULES); do \
	#	if [ ! -f "$(MODDIR)/$$filename" ]; then \
	#		echo Copying $$filename...; \
	#		cp "extra/$$filename" $(MODDIR)/; \
	#	fi; \
	#done;

post-build: main-build

main-build: pre-build
	@$(MAKE) --no-print-directory pkg

eboot: pre-build $(OBJS)
	$(CC) -v $(LDFLAGS) -o $(BLDDIR)/$(TARGET).elf $(OBJS) $(LIBS)

$(OBJDIR)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

$(OBJDIR)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

sfo:
	$(PUBCMD) sfo_create sce_sys/param.sfx $(BLDDIR)/param.sfo

pkg: sfo eboot
	$(MAKE_FSELF) --auth-info $(AUTH_INFO) $(BLDDIR)/$(TARGET).elf $(BLDDIR)/$(TARGET).self
	$(PUBCMD) img_create $(TARGET).gp4 $(BLDDIR)/$(TARGET).pkg

clean:
	@rm -rf $(OBJDIR) $(BLDDIR)
