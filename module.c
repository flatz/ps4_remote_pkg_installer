#include "module.h"
#include "util.h"

SceKernelModule sceKernelLoadStartModuleFromSandbox(const char* name, size_t args, const void* argp, unsigned int flags, const SceKernelLoadModuleOpt* opts, int* res) {
	static const char* sandboxWord = NULL;
	char filePath[SCE_KERNEL_MAX_NAME_LENGTH];
	SceKernelModule handle;

	if (!sandboxWord) {
		sandboxWord = sceKernelGetFsSandboxRandomWord();
		if (!sandboxWord) {
			return SCE_KERNEL_ERROR_EFAULT;
		}
	}

	snprintf(filePath, sizeof(filePath), "/%s/common/lib/%s", sandboxWord, name);

	handle = sceKernelLoadStartModule(filePath, args, argp, flags, opts, res);

	return handle;
}

int sceKernelGetModuleInfo(SceKernelModule handle, SceKernelModuleInfo* info) {
	int ret;

	if (!info) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}

	memset(info, 0, sizeof(*info));
	{
		info->size = sizeof(*info);
	}

	ret = syscall(SYS_dynlib_get_info, handle, info); /* TODO: make proper error code */

err:
	return ret;
}

int sceKernelGetModuleInfoByName(const char* name, SceKernelModuleInfo* info) {
	SceKernelModuleInfo tmpInfo;
	SceKernelModule handles[SCE_KERNEL_MAX_MODULES];
	size_t numModules;
	size_t i;
	int ret;

	if (!name) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}
	if (!info) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}

	memset(handles, 0, sizeof(handles));

	ret = sceKernelGetModuleList(handles, ARRAY_SIZE(handles), &numModules);
	if (ret) {
		goto err;
	}

	for (i = 0; i < numModules; ++i) {
		ret = sceKernelGetModuleInfo(handles[i], &tmpInfo);
		if (ret) {
			goto err;
		}

		if (strcmp(tmpInfo.name, name) == 0) {
			memcpy(info, &tmpInfo, sizeof(tmpInfo));
			ret = 0;
			goto err;
		}
	}

	ret = SCE_KERNEL_ERROR_ENOENT;

err:
	return ret;
}

int sceKernelGetModuleInfoEx(SceKernelModule handle, SceKernelModuleInfoEx* info) {
	int ret;

	if (!info) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}

	memset(info, 0, sizeof(*info));
	{
		info->size = sizeof(*info);
	}

	ret = syscall(SYS_dynlib_get_info_ex, handle, info); /* TODO: make proper error code */

err:
	return ret;
}

int sceKernelGetModuleInfoExByName(const char* name, SceKernelModuleInfoEx* info) {
	SceKernelModuleInfoEx tmpInfo;
	SceKernelModule handles[SCE_KERNEL_MAX_MODULES];
	size_t numModules;
	size_t i;
	int ret;

	if (!name) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}
	if (!info) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}

	memset(handles, 0, sizeof(handles));

	ret = sceKernelGetModuleList(handles, ARRAY_SIZE(handles), &numModules);
	if (ret) {
		goto err;
	}

	for (i = 0; i < numModules; ++i) {
		ret = sceKernelGetModuleInfoEx(handles[i], &tmpInfo);
		if (ret) {
			goto err;
		}

		if (strcmp(tmpInfo.name, name) == 0) {
			memcpy(info, &tmpInfo, sizeof(tmpInfo));
			ret = 0;
			goto err;
		}
	}

	ret = SCE_KERNEL_ERROR_ENOENT;

err:
	return ret;
}

int sceKernelDlsymEx(SceKernelModule handle, const char* symbol, const char* lib, unsigned int flags, void** addrp) {
	int ret;

	if (!symbol) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}
	if (!lib) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}
	if (!addrp) {
		ret = SCE_KERNEL_ERROR_EFAULT;
		goto err;
	}

	ret = syscall(SYS_supercall, SUPERCALL_DLSYM, handle, symbol, lib, flags, addrp); /* TODO: make proper error code */

err:
	return ret;
}

bool get_module_base(const char* name, uint64_t* base, uint64_t* size) {
	SceKernelModuleInfo moduleInfo;
	int ret;

	ret = sceKernelGetModuleInfoByName(name, &moduleInfo);
	if (ret) {
		EPRINTF("sceKernelGetModuleInfoByName(%s) failed: 0x%08X\n", name, ret);
		goto err;
	}

	if (base)
		*base = (uint64_t)moduleInfo.segmentInfo[0].baseAddr;
	if (size)
		*size = moduleInfo.segmentInfo[0].size;

	return true;

err:
	return false;
}

bool patch_module(const char* name, module_patch_cb_t* cb, void* arg) {
	uint64_t base, size;
	int ret;

	if (!get_module_base(name, &base, &size)) {
		goto err;
	}
	printf("%s: base:0x%" PRIX64 " size:0x%" PRIX64 "\n", name, base, size);

	ret = sceKernelMprotect((void*)base, size, SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_WRITE | SCE_KERNEL_PROT_CPU_EXEC);
	if (ret) {
		EPRINTF("sceKernelMprotect(%s) failed: 0x%08X\n", name, ret);
		goto err;
	}

	if (cb) {
		(*cb)(arg, (uint8_t*)base, size);
	}

	return true;

err:
	return false;
}
