#pragma once

#include "common.h"

bool app_inst_util_init(void);
void app_inst_util_fini(void);

bool app_inst_util_uninstall_game(const char* title_id, int* error);
bool app_inst_util_uninstall_ac(const char* content_id, int* error);
bool app_inst_util_uninstall_patch(const char* title_id, int* error);
bool app_inst_util_uninstall_theme(const char* content_id, int* error);

bool app_inst_util_is_exists(const char* title_id, bool* exists, int* error);
bool app_inst_util_get_size(const char* title_id, unsigned long* size, int* error);

struct bgft_download_task_progress_info {
	unsigned int bits;
	int error_result;
	unsigned long length;
	unsigned long transferred;
	unsigned long length_total;
	unsigned long transferred_total;
	unsigned int num_index;
	unsigned int num_total;
	unsigned int rest_sec;
	unsigned int rest_sec_total;
	int preparing_percent;
	int local_copy_percent;
};

bool bgft_init(void);
void bgft_fini(void);

bool bgft_download_register_package_task(const char* content_id, const char* content_url, const char* content_name, const char* icon_path, const char* package_type, const char* package_sub_type, unsigned long package_size, bool is_patch, int* task_id, int* error);
bool bgft_download_start_task(int task_id, int* error);
bool bgft_download_stop_task(int task_id, int* error);
bool bgft_download_pause_task(int task_id, int* error);
bool bgft_download_resume_task(int task_id, int* error);
bool bgft_download_unregister_task(int task_id, int* error);
bool bgft_download_reregister_task_patch(int old_task_id, int* new_task_id, int* error);
bool bgft_download_get_task_progress(int task_id, struct bgft_download_task_progress_info* progress_info, int* error);
bool bgft_download_find_task_by_content_id(const char* content_id, int sub_type, int* task_id, int* error);
