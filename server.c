#include "server.h"
#include "installer.h"
#include "pkg.h"
#include "sfo.h"
#include "http.h"
#include "util.h"

#include <kernel_ex.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <sandbird.h>
#include <tiny-json.h>

#define CLEANUP_DAY_COUNT 3

typedef bool handler_cb(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);

struct handler_desc {
	const char* path;
	handler_cb* handler;
	bool need_partial_match;
};

union json_value_t {
	const json_t* jval;
	const char* sval;
	int64_t ival;
};

#define THROW_ERROR(format, ...) \
	do { \
		char tmp_buf[256]; \
		snprintf(tmp_buf, sizeof(tmp_buf), format, ##__VA_ARGS__); \
		kick_error(s, 500, "Internal server error", tmp_buf); \
		goto err; \
	} while (0)

static sb_Server* s_server = NULL;
static char* s_ip_address = NULL;
static int s_port = 0;
static char* s_work_dir = NULL;

static bool s_server_started = false;

static int event_handler(sb_Event* e);

static bool handle_api_install(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_uninstall_game(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_uninstall_ac(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_uninstall_patch(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_uninstall_theme(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_is_exists(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_start_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_stop_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_pause_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_resume_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_unregister_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_get_task_progress(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);
static bool handle_api_find_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);

static bool handle_static(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size);

static void kick_error(sb_Stream* s, int code, const char* title, const char* error);
static void kick_result_header_json(sb_Stream* s);
static void kick_error_json(sb_Stream* s, int code);
static void kick_success_json(sb_Stream* s);

static void cleanup_temp_files(void);

static const struct handler_desc s_get_handlers[] = {
	{ "/static/", &handle_static, true },
};
static const struct handler_desc s_post_handlers[] = {
	{ "/api/install", &handle_api_install, false },
	{ "/api/uninstall_game", &handle_api_uninstall_game, false },
	{ "/api/uninstall_ac", &handle_api_uninstall_ac, false },
	{ "/api/uninstall_patch", &handle_api_uninstall_patch, false },
	{ "/api/uninstall_theme", &handle_api_uninstall_theme, false },
	{ "/api/is_exists", &handle_api_is_exists, false },
	{ "/api/start_task", &handle_api_start_task, false },
	{ "/api/stop_task", &handle_api_stop_task, false },
	{ "/api/pause_task", &handle_api_pause_task, false },
	{ "/api/resume_task", &handle_api_resume_task, false },
	{ "/api/unregister_task", &handle_api_unregister_task, false },
#if 0
	{ "/api/reregister_task_patch", &handle_api_reregister_task_patch, false },
#endif
	{ "/api/get_task_progress", &handle_api_get_task_progress, false },
	{ "/api/find_task", &handle_api_find_task, false },
};

bool server_start(const char* ip_address, int port, const char* work_dir) {
	sb_Options opts;
	char port_str[16];

	if (s_server_started) {
		goto done;
	}

	if (!ip_address || strlen(ip_address) == 0) {
		EPRINTF("Empty IP address specified.\n");
		goto err;
	}
	s_ip_address = strdup(ip_address);
	s_port = port;

	if (!work_dir || strlen(work_dir) == 0) {
		EPRINTF("Empty working directory specified.\n");
		goto err_free_ip_address;
	}
	s_work_dir = strdup(work_dir);

	cleanup_temp_files();

	memset(&opts, 0, sizeof(opts));
	{
		snprintf(port_str, sizeof(port_str), "%d", port);

		opts.port = port_str;
		opts.handler = &event_handler;
		opts.timeout = "0";
		opts.max_lifetime = "0";
		opts.max_request_size = "0";
	}

	s_server = sb_new_server(&opts);
	if (!s_server) {
		EPRINTF("Unable to initialize server.\n");
		goto err_work_dir_free;
	}

	s_server_started = true;

done:
	return true;

err_work_dir_free:
	free(s_work_dir);
	s_work_dir = NULL;

err_free_ip_address:
	free(s_ip_address);
	s_ip_address = NULL;

err:
	return false;
}

bool server_listen(void) {
	if (!s_server_started) {
		goto err;
	}

	for (;;) {
		sb_poll_server(s_server);
	}

	return true;

err:
	return false;
}

void server_stop(void) {
	if (!s_server_started) {
		return;
	}

	sb_close_server(s_server);
	s_server = NULL;

	free(s_work_dir);
	s_work_dir = NULL;

	free(s_ip_address);
	s_ip_address = NULL;
	s_port = 0;

	s_server_started = false;
}

static int event_handler(sb_Event* e) {
	const struct handler_desc* descs = NULL;
	handler_cb* handler = NULL;
	char* in_data;
	size_t in_size;
	size_t count;
	size_t i;
	int ret;

	if (e->type != SB_EV_REQUEST) {
		ret = SB_RES_OK;
		goto done;
	}

	if (strcasecmp(e->method, "GET") == 0) {
		descs = s_get_handlers;
		count = ARRAY_SIZE(s_get_handlers);
	} else if (strcasecmp(e->method, "POST") == 0) {
		descs = s_post_handlers;
		count = ARRAY_SIZE(s_post_handlers);
	}
	if (!descs) {
bad_request:
		kick_error(e->stream, 400, "Bad request", "Unsupported method");
		ret = SB_RES_OK;
		goto done;
	}

	for (i = 0; i < count; ++i) {
		if (descs[i].need_partial_match) {
			if (strstr(e->path, descs[i].path) == e->path) {
				handler = descs[i].handler;
				break;
			}
		} else {
			if (strcmp(e->path, descs[i].path) == 0) {
				handler = descs[i].handler;
				break;
			}
		}
	}
	if (!handler) {
		goto bad_request;
	}

	in_data = sb_get_content_data(e->stream, &in_size);

	(*handler)(e->stream, e->method, e->path, in_data, in_size);

	ret = SB_RES_OK;

done:
	return ret;
}

static inline bool handle_api_install_direct(sb_Stream* s, const json_t* root) {
	const json_t* field;
	union json_value_t val, child_val;
	char** piece_urls = NULL;
	char* unescaped_url = NULL;
	size_t unescaped_url_size;
	size_t piece_count;
	char tmp_name[32];
	char ref_pkg_json_path[SCE_KERNEL_PATH_MAX];
	char param_sfo_path[SCE_KERNEL_PATH_MAX];
	char icon0_png_path[SCE_KERNEL_PATH_MAX];
	struct sfo* sfo = NULL;
	struct sfo_entry* sfo_entry;
	char title_entry_key[16];
	char title_name[256];
	char escaped_title_name[256 * 2 + 1];
	char content_id[PKG_CONTENT_ID_SIZE + 1];
	char content_url[256];
	char icon_path[SCE_KERNEL_PATH_MAX];
	enum pkg_content_type content_type;
	const char* package_type;
	const char* package_sub_type = NULL;
	char error_buf[256];
	uint64_t package_size;
	bool is_patch;
	bool has_icon = false;
	int lang_id;
	int task_id = -1;
	size_t i;
	int ret;

	memset(ref_pkg_json_path, 0, sizeof(ref_pkg_json_path));
	memset(param_sfo_path, 0, sizeof(param_sfo_path));
	memset(icon0_png_path, 0, sizeof(icon0_png_path));

	if (!get_language_id(&lang_id)) {
		THROW_ERROR("Unable to get language id.");
	}

	field = json_getProperty(root, "packages");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "packages");
	}
	if (json_getType(field) != JSON_ARRAY) {
		THROW_ERROR("Invalid type for parameter '%s'.", "packages");
	}
	for (val.jval = json_getChild(field), piece_count = 0; val.jval != NULL; val.jval = json_getSibling(val.jval)) {
		if (json_getType(val.jval) != JSON_TEXT) {
			THROW_ERROR("Invalid type for element of parameter '%s'.", "packages");
		}
		child_val.sval = json_getValue(val.jval);
		if (strlen(child_val.sval) == 0) {
			THROW_ERROR("Empty element value of parameter '%s'.", "packages");
		}

		if (!http_unescape_uri(&unescaped_url, &unescaped_url_size, child_val.sval)) {
			THROW_ERROR("Unable to unescape element value of parameter '%s'.", "packages");
		}

		if (!starts_with(unescaped_url, "http://") && !starts_with(unescaped_url, "https://")) {
			free(unescaped_url);
			unescaped_url = NULL;
			THROW_ERROR("Unexpected element value of parameter '%s'.", "packages");
		}

		free(unescaped_url);
		unescaped_url = NULL;

		++piece_count;
	}
	if (piece_count == 0) {
		THROW_ERROR("No packages.");
	}

	piece_urls = (char**)malloc(piece_count * sizeof(*piece_urls));
	if (!piece_urls) {
		THROW_ERROR("No memory.");
	}
	memset(piece_urls, 0, piece_count * sizeof(*piece_urls));

	for (val.jval = json_getChild(field), i = 0; val.jval != NULL; val.jval = json_getSibling(val.jval)) {
		child_val.sval = json_getValue(val.jval);

		if (!http_unescape_uri(&unescaped_url, &unescaped_url_size, child_val.sval)) {
			THROW_ERROR("Unable to unescape element value of parameter '%s'.", "packages");
		}

		piece_urls[i++] = unescaped_url;
		unescaped_url = NULL;
	}

	snprintf(tmp_name, sizeof(tmp_name), "tmp_%" PRIxMAX, (uintmax_t)sb_stream_get_init_time(s) ^ (uint32_t)(uintptr_t)s);

	snprintf(ref_pkg_json_path, sizeof(ref_pkg_json_path), "%s/%s.json", s_work_dir, tmp_name);
	snprintf(param_sfo_path, sizeof(param_sfo_path), "%s/%s.sfo", s_work_dir, tmp_name);
	snprintf(icon0_png_path, sizeof(icon0_png_path), "%s/%s.png", s_work_dir, tmp_name);

	memset(error_buf, 0, sizeof(error_buf));
	if (!pkg_setup_prerequisites(piece_urls, piece_count, ref_pkg_json_path, param_sfo_path, icon0_png_path, &content_type, &package_size, &is_patch, &has_icon, error_buf, sizeof(error_buf))) {
		rtrim(error_buf);
		if (*error_buf != '\0')
			THROW_ERROR("Unable to set up prerequisites for package '%s': %s", piece_urls[0], error_buf);
		else
			THROW_ERROR("Unable to set up prerequisites for package '%s'.", piece_urls[0]);
	}

	switch (content_type) {
		case PKG_CONTENT_TYPE_GD: package_type = "PS4GD"; break;
		case PKG_CONTENT_TYPE_AC: package_type = "PS4AC"; break;
		case PKG_CONTENT_TYPE_AL: package_type = "PS4AL"; break;
		case PKG_CONTENT_TYPE_DP: package_type = "PS4DP"; break;
		default:
			package_type = NULL;
			THROW_ERROR("Unsupported content type for package '%s'.", piece_urls[0]);
			break;
	}

	sfo = sfo_alloc();
	if (!sfo) {
		THROW_ERROR("Unable to allocate system file object for package '%s'.", piece_urls[0]);
	}
	if (!sfo_load_from_file(sfo, param_sfo_path)) {
		THROW_ERROR("Unable to load system file object for package '%s'.", piece_urls[0]);
	}

	snprintf(title_entry_key, sizeof(title_entry_key), "TITLE_%02d", lang_id);
	sfo_entry = sfo_find_entry(sfo, title_entry_key);
	if (!sfo_entry) {
		strlcpy(title_entry_key, "TITLE", sizeof(title_entry_key));
		sfo_entry = sfo_find_entry(sfo, title_entry_key);
		if (!sfo_entry) {
			THROW_ERROR("Unable to get title for package '%s'.", piece_urls[0]);
		}
	}
	if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size < 1) {
		THROW_ERROR("Invalid format of '%s' entry in system file object for package '%s'.", title_entry_key, piece_urls[0]);
	}
	strlcpy(title_name, (const char*)sfo_entry->value, sizeof(title_name));

	if (!http_escape_json_string(escaped_title_name, sizeof(escaped_title_name), title_name)) {
		THROW_ERROR("Unable to escape title name.");
	}

	sfo_entry = sfo_find_entry(sfo, "CONTENT_ID");
	if (!sfo_entry) {
		THROW_ERROR("Unable to get content id for package '%s'.", piece_urls[0]);
	}
	if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size != sizeof(content_id)) {
		THROW_ERROR("Invalid format of '%s' entry in system file object for package '%s'.", "CONTENT_ID", piece_urls[0]);
	}
	strlcpy(content_id, (const char*)sfo_entry->value, sizeof(content_id));

	snprintf(content_url, sizeof(content_url), "http://%s:%d/static/%s.json", s_ip_address, s_port, tmp_name);
	snprintf(icon_path, sizeof(icon_path), "/user%s/%s.png", s_work_dir, tmp_name);

	if (bgft_download_register_package_task(content_id, content_url, title_name, has_icon ? icon_path : NULL, package_type, package_sub_type, package_size, is_patch, &task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\", \"task_id\": %d, \"title\": \"%s\" }\n", task_id, escaped_title_name);
	} else {
		kick_error_json(s, ret);
	}

	unlink(param_sfo_path);

	if (sfo) {
		sfo_free(sfo);
	}

	if (piece_urls) {
		for (i = 0; i < piece_count; ++i) {
			free(piece_urls[i]);
		}
		free(piece_urls);
	}

	if (unescaped_url) {
		free(unescaped_url);
	}

	return true;

err:
	if (strlen(ref_pkg_json_path) > 0) {
		unlink(ref_pkg_json_path);
	}
	if (strlen(param_sfo_path) > 0) {
		unlink(param_sfo_path);
	}
	if (strlen(icon0_png_path) > 0) {
		unlink(icon0_png_path);
	}

	if (sfo) {
		sfo_free(sfo);
	}

	if (piece_urls) {
		for (i = 0; i < piece_count; ++i) {
			free(piece_urls[i]);
		}
		free(piece_urls);
	}

	if (unescaped_url) {
		free(unescaped_url);
	}

	return false;
}

static inline bool handle_api_install_ref_pkg_url(sb_Stream* s, const json_t* root) {
	const json_t* field;
	union json_value_t val;
	char* unescaped_url = NULL;
	size_t unescaped_url_size;
	char** piece_urls = NULL;
	size_t piece_count;
	char tmp_name[32];
	char ref_pkg_json_path[SCE_KERNEL_PATH_MAX];
	char param_sfo_path[SCE_KERNEL_PATH_MAX];
	char icon0_png_path[SCE_KERNEL_PATH_MAX];
	struct sfo* sfo = NULL;
	struct sfo_entry* sfo_entry;
	char title_entry_key[16];
	char title_name[256];
	char escaped_title_name[256 * 2 + 1];
	char content_id[PKG_CONTENT_ID_SIZE + 1];
	char content_url[256];
	char icon_path[256];
	char error_buf[256];
	enum pkg_content_type content_type;
	const char* package_type;
	const char* package_sub_type = NULL;
	uint64_t package_size;
	bool is_patch;
	bool has_icon = false;
	int lang_id;
	int task_id = -1;
	size_t i;
	int ret;

	memset(ref_pkg_json_path, 0, sizeof(ref_pkg_json_path));
	memset(param_sfo_path, 0, sizeof(param_sfo_path));
	memset(icon0_png_path, 0, sizeof(icon0_png_path));

	if (!get_language_id(&lang_id)) {
		THROW_ERROR("Unable to get language id.");
	}

	field = json_getProperty(root, "url");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "url");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "url");
	}
	val.sval = json_getValue(field);
	if (strlen(val.sval) == 0) {
		THROW_ERROR("Empty element value of parameter '%s'.", "url");
	}

	if (!http_unescape_uri(&unescaped_url, &unescaped_url_size, val.sval)) {
		THROW_ERROR("Unable to unescape element value of parameter '%s'.", "url");
	}

	if (!starts_with(unescaped_url, "http://") && !starts_with(unescaped_url, "https://")) {
		free(unescaped_url);
		unescaped_url = NULL;
		THROW_ERROR("Unexpected element value of parameter '%s'.", "url");
	}

	piece_urls = pkg_extract_piece_urls_from_ref_pkg_json(unescaped_url, &piece_count);
	if (!piece_urls) {
		THROW_ERROR("Unable to extract pieces URLs for %s'.", unescaped_url);
	}

	snprintf(tmp_name, sizeof(tmp_name), "tmp_%" PRIxMAX, (uintmax_t)sb_stream_get_init_time(s) ^ (uint32_t)(uintptr_t)s);

	snprintf(ref_pkg_json_path, sizeof(ref_pkg_json_path), "%s/%s.json", s_work_dir, tmp_name);
	snprintf(param_sfo_path, sizeof(param_sfo_path), "%s/%s.sfo", s_work_dir, tmp_name);
	snprintf(icon0_png_path, sizeof(icon0_png_path), "%s/%s.png", s_work_dir, tmp_name);

	memset(error_buf, 0, sizeof(error_buf));
	if (!pkg_setup_prerequisites(piece_urls, piece_count, ref_pkg_json_path, param_sfo_path, icon0_png_path, &content_type, &package_size, &is_patch, &has_icon, error_buf, sizeof(error_buf))) {
		rtrim(error_buf);
		if (*error_buf != '\0')
			THROW_ERROR("Unable to set up prerequisites for package '%s': %s", piece_urls[0], error_buf);
		else
			THROW_ERROR("Unable to set up prerequisites for package '%s'.", piece_urls[0]);
	}

	switch (content_type) {
		case PKG_CONTENT_TYPE_GD: package_type = "PS4GD"; break;
		case PKG_CONTENT_TYPE_AC: package_type = "PS4AC"; break;
		case PKG_CONTENT_TYPE_AL: package_type = "PS4AL"; break;
		case PKG_CONTENT_TYPE_DP: package_type = "PS4DP"; break;
		default:
			package_type = NULL;
			THROW_ERROR("Unsupported content type for package '%s'.", piece_urls[0]);
			break;
	}

	sfo = sfo_alloc();
	if (!sfo) {
		THROW_ERROR("Unable to allocate system file object for package '%s'.", piece_urls[0]);
	}
	if (!sfo_load_from_file(sfo, param_sfo_path)) {
		THROW_ERROR("Unable to load system file object for package '%s'.", piece_urls[0]);
	}

	snprintf(title_entry_key, sizeof(title_entry_key), "TITLE_%02d", lang_id);
	sfo_entry = sfo_find_entry(sfo, title_entry_key);
	if (!sfo_entry) {
		strlcpy(title_entry_key, "TITLE", sizeof(title_entry_key));
		sfo_entry = sfo_find_entry(sfo, title_entry_key);
		if (!sfo_entry) {
			THROW_ERROR("Unable to get title for package '%s'.", piece_urls[0]);
		}
	}
	if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size < 1) {
		THROW_ERROR("Invalid format of '%s' entry in system file object for package '%s'.", title_entry_key, piece_urls[0]);
	}
	strlcpy(title_name, (const char*)sfo_entry->value, sizeof(title_name));

	if (!http_escape_json_string(escaped_title_name, sizeof(escaped_title_name), title_name)) {
		THROW_ERROR("Unable to escape title name.");
	}

	sfo_entry = sfo_find_entry(sfo, "CONTENT_ID");
	if (!sfo_entry) {
		THROW_ERROR("Unable to get content id for package '%s'.", piece_urls[0]);
	}
	if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size != sizeof(content_id)) {
		THROW_ERROR("Invalid format of '%s' entry in system file object for package '%s'.", "CONTENT_ID", piece_urls[0]);
	}
	strlcpy(content_id, (const char*)sfo_entry->value, sizeof(content_id));

	snprintf(content_url, sizeof(content_url), "http://%s:%d/static/%s.json", s_ip_address, s_port, tmp_name);
	snprintf(icon_path, sizeof(icon_path), "/user%s/%s.png", s_work_dir, tmp_name);

	if (bgft_download_register_package_task(content_id, content_url, title_name, has_icon ? icon_path : NULL, package_type, package_sub_type, package_size, is_patch, &task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\", \"task_id\": %d, \"title\": \"%s\" }\n", task_id, escaped_title_name);
	} else {
		kick_error_json(s, ret);
	}

	unlink(param_sfo_path);

	if (sfo) {
		sfo_free(sfo);
	}

	if (unescaped_url) {
		free(unescaped_url);
	}

	if (piece_urls) {
		for (i = 0; i < piece_count; ++i) {
			free(piece_urls[i]);
		}
		free(piece_urls);
	}

	return true;

err:
	if (strlen(ref_pkg_json_path) > 0) {
		unlink(ref_pkg_json_path);
	}
	if (strlen(param_sfo_path) > 0) {
		unlink(param_sfo_path);
	}
	if (strlen(icon0_png_path) > 0) {
		unlink(icon0_png_path);
	}

	if (sfo) {
		sfo_free(sfo);
	}

	if (unescaped_url) {
		free(unescaped_url);
	}

	if (piece_urls) {
		for (i = 0; i < piece_count; ++i) {
			free(piece_urls[i]);
		}
		free(piece_urls);
	}

	return false;
}

static bool handle_api_install(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	union json_value_t val;
	bool status;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "type");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "type");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "type");
	}
	val.sval = json_getValue(field);
	if (strcasecmp(val.sval, "direct") == 0) {
		status = handle_api_install_direct(s, root);
	} else if (strcasecmp(val.sval, "ref_pkg_url") == 0) {
		status = handle_api_install_ref_pkg_url(s, root);
	} else {
		THROW_ERROR("Invalid type '%s'.", val.sval);
	}

	if (pool) {
		free(pool);
	}

	return status;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_uninstall_game(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	char title_id[PKG_TITLE_ID_SIZE + 1];
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "title_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "title_id");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "title_id");
	}
	val.sval = json_getValue(field);

	strlcpy(title_id, val.sval, sizeof(title_id));

	if (app_inst_util_uninstall_game(title_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_uninstall_ac(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	char content_id[PKG_CONTENT_ID_SIZE + 1];
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "content_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "content_id");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "content_id");
	}
	val.sval = json_getValue(field);

	strlcpy(content_id, val.sval, sizeof(content_id));

	if (app_inst_util_uninstall_ac(content_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_uninstall_patch(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	char title_id[PKG_TITLE_ID_SIZE + 1];
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "title_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "title_id");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "title_id");
	}
	val.sval = json_getValue(field);

	strlcpy(title_id, val.sval, sizeof(title_id));

	if (app_inst_util_uninstall_patch(title_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_uninstall_theme(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	char content_id[PKG_CONTENT_ID_SIZE + 1];
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "content_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "content_id");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "content_id");
	}
	val.sval = json_getValue(field);

	strlcpy(content_id, val.sval, sizeof(content_id));

	if (app_inst_util_uninstall_theme(content_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_is_exists(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	char title_id[PKG_TITLE_ID_SIZE + 1];
	union json_value_t val;
	unsigned long size;
	bool exists;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "title_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "title_id");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "title_id");
	}
	val.sval = json_getValue(field);

	strlcpy(title_id, val.sval, sizeof(title_id));

	if (app_inst_util_is_exists(title_id, &exists, &ret)) {
		kick_result_header_json(s);
		if (exists) {
			if (!app_inst_util_get_size(title_id, &size, &ret)) {
				size = (unsigned long)-1;
			}
			sb_writef(s, "{ \"status\": \"success\", \"exists\": \"%s\", \"size\": 0x%" PRIXMAX " }\n", exists ? "true" : "false", (uintmax_t)size);
		} else {
			sb_writef(s, "{ \"status\": \"success\", \"exists\": \"%s\" }\n", exists ? "true" : "false");
		}
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_start_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	int task_id;
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "task_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "task_id");
	}
	if (json_getType(field) != JSON_INTEGER) {
		THROW_ERROR("Invalid type for parameter '%s'.", "task_id");
	}
	val.ival = (int)json_getInteger(field);

	task_id = val.ival;
	if (task_id < 0) {
		THROW_ERROR("Invalid value for '%s' parameter specified.", "task_id");
	}

	if (bgft_download_start_task(task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_stop_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	int task_id;
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "task_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "task_id");
	}
	if (json_getType(field) != JSON_INTEGER) {
		THROW_ERROR("Invalid type for parameter '%s'.", "task_id");
	}
	val.ival = (int)json_getInteger(field);

	task_id = val.ival;
	if (task_id < 0) {
		THROW_ERROR("Invalid value for '%s' parameter specified.", "task_id");
	}

	if (bgft_download_stop_task(task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_pause_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	int task_id;
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "task_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "task_id");
	}
	if (json_getType(field) != JSON_INTEGER) {
		THROW_ERROR("Invalid type for parameter '%s'.", "task_id");
	}
	val.ival = (int)json_getInteger(field);

	task_id = val.ival;
	if (task_id < 0) {
		THROW_ERROR("Invalid value for '%s' parameter specified.", "task_id");
	}

	if (bgft_download_pause_task(task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_resume_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	int task_id;
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "task_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "task_id");
	}
	if (json_getType(field) != JSON_INTEGER) {
		THROW_ERROR("Invalid type for parameter '%s'.", "task_id");
	}
	val.ival = (int)json_getInteger(field);

	task_id = val.ival;
	if (task_id < 0) {
		THROW_ERROR("Invalid value for '%s' parameter specified.", "task_id");
	}

	if (bgft_download_resume_task(task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_unregister_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	int task_id;
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "task_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "task_id");
	}
	if (json_getType(field) != JSON_INTEGER) {
		THROW_ERROR("Invalid type for parameter '%s'.", "task_id");
	}
	val.ival = (int)json_getInteger(field);

	task_id = val.ival;
	if (task_id < 0) {
		THROW_ERROR("Invalid value for '%s' parameter specified.", "task_id");
	}

	if (bgft_download_unregister_task(task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\" }\n");
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_get_task_progress(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	int task_id;
	struct bgft_download_task_progress_info progress_info;
	union json_value_t val;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "task_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "task_id");
	}
	if (json_getType(field) != JSON_INTEGER) {
		THROW_ERROR("Invalid type for parameter '%s'.", "task_id");
	}
	val.ival = (int)json_getInteger(field);

	task_id = val.ival;
	if (task_id < 0) {
		THROW_ERROR("Invalid value for '%s' parameter specified.", "task_id");
	}

	if (bgft_download_get_task_progress(task_id, &progress_info, &ret)) {
		kick_result_header_json(s);

		/* TODO: make bits field more user-friendly */
		sb_writef(s,
			"{ \"status\": \"success\", \"bits\": 0x%" PRIX32 ", \"error\": %d, \"length\": 0x%" PRIXMAX ", \"transferred\": 0x%" PRIXMAX ", \"length_total\": 0x%" PRIXMAX ", \"transferred_total\": 0x%" PRIXMAX ", \"num_index\": %" PRIu32 ", \"num_total\": %" PRIu32 ", \"rest_sec\": %" PRIu32 ", \"rest_sec_total\": %" PRIu32 ", \"preparing_percent\": %" PRId32 ", \"local_copy_percent\": %" PRId32 " }\n",
			progress_info.bits, progress_info.error_result, (uintmax_t)progress_info.length, (uintmax_t)progress_info.transferred, (uintmax_t)progress_info.length_total, (uintmax_t)progress_info.transferred_total, progress_info.num_index, progress_info.num_total, progress_info.rest_sec, progress_info.rest_sec_total, progress_info.preparing_percent, progress_info.local_copy_percent
		);
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_api_find_task(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	union json_value_t val;
	char content_id[PKG_CONTENT_ID_SIZE + 1];
	int sub_type;
	int task_id = -1;
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);
	assert(in_data != NULL);

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		THROW_ERROR("No memory.");
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(in_data, pool, pool_size);
	if (!root) {
		THROW_ERROR("Invalid JSON format.");
	}

	field = json_getProperty(root, "content_id");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "content_id");
	}
	if (json_getType(field) != JSON_TEXT) {
		THROW_ERROR("Invalid type for parameter '%s'.", "content_id");
	}
	val.sval = json_getValue(field);

	strlcpy(content_id, val.sval, sizeof(content_id));

	field = json_getProperty(root, "sub_type");
	if (!field) {
		THROW_ERROR("No '%s' parameter specified.", "sub_type");
	}
	if (json_getType(field) != JSON_INTEGER) {
		THROW_ERROR("Invalid type for parameter '%s'.", "sub_type");
	}
	val.ival = (int)json_getInteger(field);

	sub_type = val.ival;

	if (bgft_download_find_task_by_content_id(content_id, sub_type, &task_id, &ret)) {
		kick_result_header_json(s);
		sb_writef(s, "{ \"status\": \"success\", \"task_id\": %d }\n", task_id);
	} else {
		kick_error_json(s, ret);
	}

	if (pool) {
		free(pool);
	}

	return true;

err:
	if (pool) {
		free(pool);
	}

	return false;
}

static bool handle_static(sb_Stream* s, const char* method, const char* path, char* in_data, size_t in_size) {
	struct stat stbuf;
	const char* content_type;
	char real_path[SCE_KERNEL_PATH_MAX];
	int ret;

	assert(s != NULL);
	assert(method != NULL);
	assert(path != NULL);

	if (!starts_with(path, "/static/") || strstr(path, ":/") || strstr(path, "..")) {
		kick_error(s, 400, "Bad request", "Invalid path");
		ret = SB_RES_OK;
		goto done;
	}
	path += strlen("/static/");

	snprintf(real_path, sizeof(real_path), "%s/%s", s_work_dir, path);

	ret = stat(real_path, &stbuf);
	if (ret < 0) {
		kick_error(s, 404, "Not found", "Page not found");
		ret = SB_RES_OK;
		goto done;
	}

	if (!S_ISREG(stbuf.st_mode)) {
		kick_error(s, 403, "Forbidden", "Access is denied");
		ret = SB_RES_OK;
		goto done;
	}

	if (ends_with_nocase(real_path, ".json")) {
		content_type = "application/json";
	} else if (ends_with_nocase(real_path, ".png")) {
		content_type = "image/png";
	} else {
		content_type = "application/octet-stream";
	}

	sb_send_status(s, 200, "OK");
	sb_send_header(s, "Connection", "close");
	sb_send_header(s, "Content-Type", content_type);

	ret = sb_send_file(s, real_path);
	if (ret) {
		kick_error(s, 500, "Internal server error", sb_error_str(ret));
		goto done;
	}

done:
	return (ret == SB_RES_OK);
}

static void kick_error(sb_Stream* s, int code, const char* title, const char* error) {
	char escaped_error[1024];

	if (!error) {
		error = "Unknown";
	}

	sb_send_status(s, code, title);
	sb_send_header(s, "Content-Type", "application/json");
	sb_send_header(s, "Access-Control-Allow-Origin", "*");
	sb_send_header(s, "Connection", "close");

	if (!http_escape_json_string(escaped_error, sizeof(escaped_error), error)) {
		strlcpy(escaped_error, "Unable to escape error string.", sizeof(escaped_error));
	}

	sb_writef(s, "{ \"status\": \"fail\", \"error\": \"%s\" }\n", escaped_error);
}

static void kick_result_header_json(sb_Stream* s) {
	sb_send_status(s, 200, "OK");
	sb_send_header(s, "Content-Type", "application/json");
	sb_send_header(s, "Access-Control-Allow-Origin", "*");
	sb_send_header(s, "Connection", "close");
}

static void kick_error_json(sb_Stream* s, int code) {
	kick_result_header_json(s);
	sb_writef(s, "{ \"status\": \"fail\", \"error_code\": 0x%08X }\n", code);
}

static void kick_success_json(sb_Stream* s) {
	kick_result_header_json(s);
	sb_writef(s, "{ \"status\": \"success\" }\n");
}

static void cleanup_temp_files(void) {
	char full_path[SCE_KERNEL_PATH_MAX];
	char buf[8192];
	SceKernelDirent* entry;
	SceKernelStat stat_buf;
	struct timespec now, diff;
	int fd = -1;
	int ret;

	if (!timespec_now(&now)) {
		goto err;
	}

	fd = ret = sceKernelOpen(s_work_dir, O_RDONLY, 0);
	if (ret < 0) {
		EPRINTF("sceKernelOpen failed: 0x%08X\n", ret);
		goto err;
	}

	for (;;) {
		memset(buf, 0, sizeof(buf));

		ret = sceKernelGetdents(fd, buf, sizeof(buf));
		if (ret < 0) {
			EPRINTF("sceKernelGetdents failed: 0x%08X\n", ret);
			goto err;
		}
		if (ret == 0) {
			break;
		}
		entry = (SceKernelDirent*)buf;

		while (entry->d_fileno != 0) {
			if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 && entry->d_type == SCE_KERNEL_DT_REG) {
				snprintf(full_path, sizeof(full_path), "%s/%s", s_work_dir, entry->d_name);

				if (starts_with(entry->d_name, "tmp_") && (ends_with(entry->d_name, ".json") || ends_with(entry->d_name, ".sfo") || ends_with(entry->d_name, ".png"))) {
					ret = sceKernelStat(full_path, &stat_buf);
					if (ret) {
						EPRINTF("sceKernelStat failed: 0x%08X\n", ret);
						goto err;
					}

					if (timespec_compare(&now, &stat_buf.st_atim) >= 0) {
						timespec_sub(&diff, &now, &stat_buf.st_atim);

						if (diff.tv_sec >= (long)CLEANUP_DAY_COUNT * 24 * 60 * 60) {
							unlink(full_path);
						}
					}
				}
			}

			entry = (SceKernelDirent*)((char*)entry + entry->d_reclen);
		}
	}

err:
	if (fd > 0) {
		ret = sceKernelClose(fd);
		if (ret) {
			EPRINTF("sceKernelClose failed: 0x%08X\n", ret);
		}
	}
}
