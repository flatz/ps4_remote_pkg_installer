#pragma once

#include "common.h"

#include <kernel_ex.h>

#define DLSYM_MANGLED_NAME 0x1

SceKernelModule sceKernelLoadStartModuleFromSandbox(const char* name, size_t args, const void* argp, unsigned int flags, const SceKernelLoadModuleOpt* opts, int* res);

int sceKernelGetModuleInfo(SceKernelModule handle, SceKernelModuleInfo* info);
int sceKernelGetModuleInfoEx(SceKernelModule handle, SceKernelModuleInfoEx* info);

int sceKernelGetModuleInfoByName(const char* name, SceKernelModuleInfo* info);
int sceKernelGetModuleInfoExByName(const char* name, SceKernelModuleInfoEx* info);

int sceKernelDlsymEx(SceKernelModule handle, const char* symbol, const char* lib, unsigned int flags, void** addrp);

bool get_module_base(const char* name, uint64_t* base, uint64_t* size);

typedef void module_patch_cb_t(void* arg, uint8_t* base, uint64_t size);
bool patch_module(const char* name, module_patch_cb_t* cb, void* arg);
