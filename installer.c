#include "installer.h"
#include "pkg.h"
#include "util.h"

#include <kernel_ex.h>
#include <user_service_ex.h>
#include <appinst_util.h>
#include <bgft.h>
#include <sys/param.h>

#define BGFT_HEAP_SIZE (1 * 1024 * 1024)

#define WAIT_TIME (UINT64_C(5) * 1000 * 1000) /* 5 secs */

static SceBgftInitParams s_bgft_init_params;

static bool s_app_inst_util_initialized = false;
static bool s_bgft_initialized = false;

static bool modify_download_task_for_patch_internal(const char* path, int index);
static bool modify_download_task_for_patch(SceBgftTaskId task_id);

bool app_inst_util_init(void) {
	int ret;

	if (s_app_inst_util_initialized) {
		goto done;
	}

	ret = sceAppInstUtilInitialize();
	if (ret) {
		EPRINTF("sceAppInstUtilInitialize failed: 0x%08X\n", ret);
		goto err;
	}

	s_app_inst_util_initialized = true;

done:
	return true;

err:
	s_app_inst_util_initialized = false;

	return false;
}

void app_inst_util_fini(void) {
	int ret;

	if (!s_app_inst_util_initialized) {
		return;
	}

	ret = sceAppInstUtilTerminate();
	if (ret) {
		EPRINTF("sceAppInstUtilTerminate failed: 0x%08X\n", ret);
	}

	s_app_inst_util_initialized = false;
}

bool app_inst_util_uninstall_game(const char* title_id, int* error) {
	int ret;

	if (!s_app_inst_util_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!title_id) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceAppInstUtilAppUnInstall(title_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceAppInstUtilAppUnInstall failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool app_inst_util_uninstall_ac(const char* content_id, int* error) {
	struct pkg_content_info content_info;
	int ret;

	if (!s_app_inst_util_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!content_id) {
invalid_content_id:
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}
	if (!pkg_parse_content_id(content_id, &content_info)) {
		goto invalid_content_id;
	}

	ret = sceAppInstUtilAppUnInstallAddcont(content_info.title_id, content_info.label);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceAppInstUtilAppUnInstallAddcont failed: 0x%08X\n", ret);
		goto err;
	}

done:
	return true;

err:
	return false;
}

bool app_inst_util_uninstall_patch(const char* title_id, int* error) {
	int ret;

	if (!s_app_inst_util_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!title_id) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceAppInstUtilAppUnInstallPat(title_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceAppInstUtilAppUnInstallPat failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool app_inst_util_uninstall_theme(const char* content_id, int* error) {
	int ret;

	if (!s_app_inst_util_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!content_id) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceAppInstUtilAppUnInstallTheme(content_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceAppInstUtilAppUnInstallTheme failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool app_inst_util_is_exists(const char* title_id, bool* exists, int* error) {
	int flag;
	int ret;

	if (!s_app_inst_util_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!title_id) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceAppInstUtilAppExists(title_id, &flag);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceAppInstUtilAppExists failed: 0x%08X\n", ret);
		goto err;
	}

	if (exists) {
		*exists = flag;
	}

	return true;

err:
	return false;
}

bool app_inst_util_get_size(const char* title_id, unsigned long* size, int* error) {
	int ret;

	if (!s_app_inst_util_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!title_id) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceAppInstUtilAppGetSize(title_id, size);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceAppInstUtilAppGetSize failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool bgft_init(void) {
	int ret;

	if (s_bgft_initialized) {
		goto done;
	}

	memset(&s_bgft_init_params, 0, sizeof(s_bgft_init_params));
	{
		s_bgft_init_params.heapSize = BGFT_HEAP_SIZE;
		s_bgft_init_params.heap = (uint8_t*)malloc(s_bgft_init_params.heapSize);
		if (!s_bgft_init_params.heap) {
			EPRINTF("No memory for BGFT heap.\n");
			goto err;
		}
		memset(s_bgft_init_params.heap, 0, s_bgft_init_params.heapSize);
	}

	ret = sceBgftInitialize(&s_bgft_init_params);
	if (ret) {
		EPRINTF("sceBgftInitialize failed: 0x%08X\n", ret);
		goto err_bgft_heap_free;
	}

	s_bgft_initialized = true;

done:
	return true;

err_bgft_heap_free:
	if (s_bgft_init_params.heap) {
		free(s_bgft_init_params.heap);
		s_bgft_init_params.heap = NULL;
	}

	memset(&s_bgft_init_params, 0, sizeof(s_bgft_init_params));

err:
	s_bgft_initialized = false;

	return false;
}

void bgft_fini(void) {
	int ret;

	if (!s_bgft_initialized) {
		return;
	}

	ret = sceBgftFinalize();
	if (ret) {
		EPRINTF("sceBgftFinalize failed: 0x%08X\n", ret);
	}

	if (s_bgft_init_params.heap) {
		free(s_bgft_init_params.heap);
		s_bgft_init_params.heap = NULL;
	}

	memset(&s_bgft_init_params, 0, sizeof(s_bgft_init_params));

	s_bgft_initialized = false;
}

bool bgft_download_register_package_task(const char* content_id, const char* content_url, const char* content_name, const char* icon_path, const char* package_type, const char* package_sub_type, unsigned long package_size, bool is_patch, int* out_task_id, int* error) {
	SceBgftDownloadParam params;
	SceBgftDownloadRegisterErrorInfo error_info;
	SceBgftTaskId task_id;
	struct pkg_content_info content_info;
	int user_id;
	int ret;

	if (!s_app_inst_util_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}
	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!pkg_parse_content_id(content_id, &content_info)) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceUserServiceGetForegroundUser(&user_id);
	if (ret) {
		EPRINTF("sceUserServiceGetForegroundUser failed: 0x%08X\n", ret);
		goto err;
	}

	memset(&error_info, 0, sizeof(error_info));

	memset(&params, 0, sizeof(params));
	{
		params.entitlementType = 5; /* TODO: figure out */
		params.userId = user_id;
		params.id = content_id;
		params.contentUrl = content_url;
		params.contentName = content_name;
		params.iconPath = icon_path ? icon_path : "";
		params.playgoScenarioId = "0";
		params.option = SCE_BGFT_TASK_OPT_DISABLE_CDN_QUERY_PARAM;
		params.packageType = package_type;
		params.packageSubType = package_sub_type ? package_sub_type : "";
		params.packageSize = package_size;
	}

	task_id = SCE_BGFT_INVALID_TASK_ID;

	if (!is_patch) {
		ret = sceBgftDownloadRegisterTask(&params, &task_id);
		//ret = sceBgftDownloadRegisterTaskStoreWithErrorInfo(&params, &task_id, &error_info);
	} else {
		ret = sceBgftDebugDownloadRegisterPkg(&params, &task_id);
	}
	if (ret) {
		if (error) {
			*error = ret;
		}
		if (ret == SCE_BGFT_ERROR_SAME_APPLICATION_ALREADY_INSTALLED) {
			task_id = -1;
			//printf("Package already installed.\n");
			goto done;
		}
		EPRINTF("sceBgftDownloadRegisterTask failed: 0x%08X\n", ret);
		goto err;
	}

done:
	if (out_task_id) {
		*out_task_id = (int)task_id;
	}

	return true;

err:
	return false;
}

bool bgft_download_start_task(int task_id, int* error) {
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (task_id < 0) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceBgftDownloadStartTask((SceBgftTaskId)task_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftDownloadStartTask failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool bgft_download_stop_task(int task_id, int* error) {
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (task_id < 0) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceBgftDownloadStopTask((SceBgftTaskId)task_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftDownloadStopTask failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool bgft_download_pause_task(int task_id, int* error) {
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (task_id < 0) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceBgftDownloadPauseTask((SceBgftTaskId)task_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftDownloadPauseTask failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool bgft_download_resume_task(int task_id, int* error) {
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (task_id < 0) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceBgftDownloadResumeTask((SceBgftTaskId)task_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftDownloadResumeTask failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool bgft_download_unregister_task(int task_id, int* error) {
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (task_id < 0) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	ret = sceBgftDownloadUnregisterTask((SceBgftTaskId)task_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftDownloadUnregisterTask failed: 0x%08X\n", ret);
		goto err;
	}

	return true;

err:
	return false;
}

bool bgft_download_reregister_task_patch(int old_task_id, int* new_task_id, int* error) {
	SceBgftTaskId tmp_id;
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (old_task_id < 0) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	tmp_id = SCE_BGFT_INVALID_TASK_ID;
	ret = sceBgftDownloadReregisterTaskPatch((SceBgftTaskId)old_task_id, &tmp_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftDownloadReregisterTaskPatch failed: 0x%08X\n", ret);
		goto err;
	}

	if (new_task_id) {
		*new_task_id = (int)tmp_id;
	}

	return true;

err:
	return false;
}

bool bgft_download_get_task_progress(int task_id, struct bgft_download_task_progress_info* progress_info, int* error) {
	SceBgftTaskProgress tmp_progress_info;
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (task_id < 0) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}
	if (!progress_info) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	memset(&tmp_progress_info, 0, sizeof(tmp_progress_info));
	ret = sceBgftDownloadGetProgress((SceBgftTaskId)task_id, &tmp_progress_info);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftDownloadGetProgress failed: 0x%08X\n", ret);
		goto err;
	}

	memset(progress_info, 0, sizeof(*progress_info));
	{
		progress_info->bits = tmp_progress_info.bits;
		progress_info->error_result = tmp_progress_info.errorResult;
		progress_info->length = tmp_progress_info.length;
		progress_info->transferred = tmp_progress_info.transferred;
		progress_info->length_total = tmp_progress_info.lengthTotal;
		progress_info->transferred_total = tmp_progress_info.transferredTotal;
		progress_info->num_index = tmp_progress_info.numIndex;
		progress_info->num_total = tmp_progress_info.numTotal;
		progress_info->rest_sec = tmp_progress_info.restSec;
		progress_info->rest_sec_total = tmp_progress_info.restSecTotal;
		progress_info->preparing_percent = tmp_progress_info.preparingPercent;
		progress_info->local_copy_percent = tmp_progress_info.localCopyPercent;
	}

	return true;

err:
	return false;
}

bool bgft_download_find_task_by_content_id(const char* content_id, int sub_type, int* task_id, int* error) {
	SceBgftTaskId tmp_id;
	int ret;

	if (!s_bgft_initialized) {
		ret = SCE_KERNEL_ERROR_ENXIO;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	if (!content_id) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}
	if (!((SceBgftTaskSubType)sub_type > SCE_BGFT_TASK_SUB_TYPE_UNKNOWN && (SceBgftTaskSubType)sub_type < SCE_BGFT_TASK_SUB_TYPE_MAX)) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		if (error) {
			*error = ret;
		}
		goto err;
	}

	tmp_id = SCE_BGFT_INVALID_TASK_ID;
	ret = sceBgftServiceDownloadFindTaskByContentId(content_id, (SceBgftTaskSubType)sub_type, &tmp_id);
	if (ret) {
		if (error) {
			*error = ret;
		}
		EPRINTF("sceBgftServiceDownloadFindTaskByContentId failed: 0x%08X\n", ret);
		goto err;
	}

	if (task_id) {
		*task_id = (int)tmp_id;
	}

	return true;

err:
	return false;
}
