#include "pkg.h"
#include "http.h"
#include "util.h"

#include <kernel_ex.h>
#include <tiny-json.h>

//#define ESCAPE_URL

union json_value_t {
	const json_t* jval;
	const char* sval;
	int64_t ival;
};

static uint8_t s_zero_mini_digest[PKG_MINI_DIGEST_SIZE] = { 0 };

bool pkg_parse_content_id(const char* content_id, struct pkg_content_info* info) {
	struct pkg_content_info tmp;
	char* p1;
	char* p2;
	bool status = false;

	if (!content_id) {
		goto err;
	}

	if (strlen(content_id) != PKG_CONTENT_ID_SIZE) {
		goto err;
	}

	memset(&tmp, 0, sizeof(tmp));
	strlcpy(tmp.content_id, content_id, sizeof(tmp.content_id));

	p1 = strchr(content_id, '-');
	if (!p1) {
		goto err;
	}
	p2 = strchr(++p1, '-');
	if (!p2) {
		goto err;
	}
	if ((p2 - content_id) != PKG_SERVICE_ID_SIZE) {
		goto err;
	}
	strlcpy(tmp.service_id, content_id, sizeof(tmp.service_id));
	if (strlen(tmp.service_id) != PKG_SERVICE_ID_SIZE) {
		goto err;
	}

	p2 = strchr(p1, '_');
	if (!p2) {
		goto err;
	}
	strlcpy(tmp.title_id, p1, sizeof(tmp.title_id));
	if (strlen(tmp.title_id) != PKG_TITLE_ID_SIZE) {
		goto err;
	}

	p1 = strrchr(content_id, '-');
	if (!p1) {
		goto err;
	}
	strlcpy(tmp.label, p1 + 1, sizeof(tmp.label));
	if (strlen(tmp.label) != PKG_LABEL_SIZE) {
		goto err;
	}

	if (info) {
		memcpy(info, &tmp, sizeof(*info));
	}

	status = true;

err:
	return status;
}

char** pkg_extract_piece_urls_from_ref_pkg_json(const char* url, size_t* piece_count) {
	static json_t* pool = NULL;
	const size_t pool_size = 256;
	const json_t* root;
	const json_t* field;
	union json_value_t val;
	const char* prop_val;
	char* data = NULL;
	uint64_t size = (uint64_t)-1;
	uint64_t total_size;
	char** piece_urls = NULL;
	size_t count;
	char* unescaped_url = NULL;
	size_t unescaped_url_size;
	size_t i;

	if (!url) {
		EPRINTF("No URL specified.\n");
		goto err;
	}

	//printf("Downloading reference package json: %s\n", url);
	if (!http_download_file(url, (uint8_t**)&data, &size, &total_size, 0)) {
		EPRINTF("Unable to download reference package json '%s'.\n", url);
		goto err;
	}
	//printf("Reference package json total size: 0x%" PRIX64 "\n", total_size);
	if (total_size == 0) {
		EPRINTF("Empty reference package json.\n");
		goto err;
	}

	pool = (json_t*)malloc(sizeof(*pool) * pool_size);
	if (!pool) {
		EPRINTF("No memory.\n");
		goto err;
	}
	memset(pool, 0, sizeof(*pool) * pool_size);

	root = json_create(data, pool, pool_size);
	if (!root) {
		EPRINTF("Invalid JSON format.\n");
		goto err;
	}

	field = json_getProperty(root, "pieces");
	if (!field) {
		EPRINTF("No '%s' parameter found.\n", "pieces");
		goto err;
	}
	if (json_getType(field) != JSON_ARRAY) {
		EPRINTF("Invalid type for parameter '%s'.\n", "pieces");
		goto err;
	}
	for (val.jval = json_getChild(field), count = 0; val.jval != NULL; val.jval = json_getSibling(val.jval)) {
		if (json_getType(val.jval) != JSON_OBJ) {
			EPRINTF("Invalid type for element of parameter '%s'.\n", "pieces");
			goto err;
		}

		prop_val = json_getPropertyValue(val.jval, "url");
		if (!prop_val) {
			EPRINTF("No '%s' property found in element of parameter '%s'.\n", "url", "pieces");
			goto err;
		}
		if (strlen(prop_val) == 0) {
			EPRINTF("Empty value of property '%s' in element of parameter '%s'.\n", "url", "pieces");
			goto err;
		}

		if (!http_unescape_uri(&unescaped_url, &unescaped_url_size, prop_val)) {
			EPRINTF("Unable to unescape value of property '%s' in element of parameter '%s'.\n", "url", "pieces");
			goto err;
		}

		if (!starts_with(unescaped_url, "http://") && !starts_with(unescaped_url, "https://")) {
			EPRINTF("Unexpected value of property '%s' in element of parameter '%s'.\n", "url", "pieces");
			goto err;
		}

		free(unescaped_url);
		unescaped_url = NULL;

		++count;
	}
	if (count == 0) {
		EPRINTF("No pieces.\n");
		goto err;
	}

	piece_urls = (char**)malloc(count * sizeof(*piece_urls));
	if (!piece_urls) {
		EPRINTF("No memory.\n");
		goto err;
	}
	memset(piece_urls, 0, count * sizeof(*piece_urls));

	for (val.jval = json_getChild(field), i = 0; val.jval != NULL; val.jval = json_getSibling(val.jval)) {
		prop_val = json_getPropertyValue(val.jval, "url");

		if (!http_unescape_uri(&unescaped_url, &unescaped_url_size, prop_val)) {
			EPRINTF("Unable to unescape value of property '%s' in element of parameter '%s'.\n", "url", "pieces");
			goto err;
		}

		piece_urls[i++] = unescaped_url;
		unescaped_url = NULL;
	}

	if (piece_count) {
		*piece_count = count;
	}

	if (unescaped_url) {
		free(unescaped_url);
	}

	if (data) {
		free(data);
	}

	return piece_urls;

err:
	if (piece_count) {
		*piece_count = 0;
	}

	if (piece_urls) {
		for (i = 0; i < count; ++i) {
			free(piece_urls[i]);
		}
		free(piece_urls);
	}

	if (unescaped_url) {
		free(unescaped_url);
	}

	if (data) {
		free(data);
	}

	return NULL;
}

#define PKG_THROW_ERROR(format, ...) \
	do { \
		if (error_buf) \
			snprintf(error_buf, error_buf_size, format, ##__VA_ARGS__); \
		EPRINTF(format, ##__VA_ARGS__); \
	} while (0)

bool pkg_setup_prerequisites(char** piece_urls, size_t piece_count, const char* ref_pkg_json_path, const char* param_sfo_path, const char* icon0_png_path, enum pkg_content_type* content_type, uint64_t* package_size, bool* is_patch, bool* has_icon, char* error_buf, size_t error_buf_size) {
	static const uint8_t magic[] = { '\x7F', 'C', 'N', 'T' };
	struct pkg_header* hdr;
	struct pkg_table_entry* entries;
	uint8_t* hdr_data = NULL;
	uint64_t hdr_size = sizeof(*hdr);
	uint8_t* entry_table_data = NULL;
	uint32_t entry_table_offset;
	uint64_t entry_table_size;
	uint8_t* param_sfo_data = NULL;
	uint32_t param_sfo_offset = 0;
	uint32_t param_sfo_size = 0;
	uint64_t param_sfo_dl_size;
	uint8_t* icon0_png_data = NULL;
	uint32_t icon0_png_offset = 0;
	uint32_t icon0_png_size = 0;
	uint64_t icon0_png_dl_size;
	uint64_t offset, total_size;
	size_t entry_count;
	char pkg_digest_str[PKG_DIGEST_SIZE * 2 + 1];
	char piece_digest_str[PKG_MINI_DIGEST_SIZE * 2 + 1];
#ifdef ESCAPE_URL
	char* escaped_url = NULL;
	size_t escaped_url_size;
#endif
	FILE* fp = NULL;
	size_t i;
	bool status = false;

	if (!piece_urls) {
		PKG_THROW_ERROR("No pieces URLs specified.\n");
		goto err;
	}
	if (piece_count == 0) {
		PKG_THROW_ERROR("No pieces.\n");
		goto err;
	}
	if (!ref_pkg_json_path || strlen(ref_pkg_json_path) == 0) {
		PKG_THROW_ERROR("Empty reference package json file path specified.\n");
		goto err;
	}
	if (!param_sfo_path || strlen(param_sfo_path) == 0) {
		PKG_THROW_ERROR("Empty param.sfo file path specified.\n");
		goto err;
	}
	if (!icon0_png_path || strlen(icon0_png_path) == 0) {
		PKG_THROW_ERROR("Empty icon0.png file path specified.\n");
		goto err;
	}

	unlink(ref_pkg_json_path);
	unlink(param_sfo_path);
	unlink(icon0_png_path);

	//printf("Downloading package header: %s\n", piece_urls[0]);
	if (!http_download_file(piece_urls[0], &hdr_data, &hdr_size, &total_size, 0)) {
		PKG_THROW_ERROR("Unable to download package header for '%s'.\n", piece_urls[0]);
		goto err;
	}
	//printf("Package header size: 0x%" PRIX64 "\n", hdr_size);
	if (hdr_size != sizeof(*hdr)) {
		PKG_THROW_ERROR("Package header size mismatch for '%s'.\n", piece_urls[0]);
		goto err;
	}
	//printf("Package total size: 0x%" PRIX64 "\n", total_size);

	hdr = (struct pkg_header*)hdr_data;

	if (memcmp(hdr->magic, magic, sizeof(magic)) != 0) {
		PKG_THROW_ERROR("Invalid package format for '%s'.\n", piece_urls[0]);
		goto err;
	}

	if (is_patch) {
		*is_patch = pkg_is_patch(hdr);
	}

	if (piece_count == 1 && BE64(hdr->package_size) > 0 && total_size != BE64(hdr->package_size)) {
		PKG_THROW_ERROR("Unexpected file size for '%s'.\n", piece_urls[0]);
		goto err;
	}

	entry_count = BE32(hdr->entry_count);
	entry_table_offset = BE32(hdr->entry_table_offset);
	entry_table_size = entry_count * sizeof(*entries);
	if (entry_table_size == 0) {
		PKG_THROW_ERROR("Empty entry table for '%s'.\n", piece_urls[0]);
		goto err;
	}

	//printf("Downloading package entry table: %s\n", piece_urls[0]);
	if (!http_download_file(piece_urls[0], &entry_table_data, &entry_table_size, NULL, entry_table_offset)) {
		PKG_THROW_ERROR("Unable to download package entry table for '%s'.\n", piece_urls[0]);
		goto err;
	}
	//printf("Package entry table size: 0x%" PRIX64 "\n", entry_table_size);
	if (entry_table_size != entry_count * sizeof(*entries)) {
		PKG_THROW_ERROR("Package entry table size mismatch for '%s'.\n", piece_urls[0]);
		goto err;
	}

	entries = (struct pkg_table_entry*)entry_table_data;
	for (i = 0; i < entry_count; ++i) {
		switch (BE32(entries[i].id)) {
			case PKG_ENTRY_ID__PARAM_SFO:
				param_sfo_offset = BE32(entries[i].offset);
				param_sfo_size = BE32(entries[i].size);
				break;
			case PKG_ENTRY_ID__ICON0_PNG:
				icon0_png_offset = BE32(entries[i].offset);
				icon0_png_size = BE32(entries[i].size);
				break;
			default:
				goto next;
		}
next:;
	}

	if (param_sfo_offset > 0 && param_sfo_size > 0) {
		//printf("Downloading %s: %s\n", "param.sfo", piece_urls[0]);
		param_sfo_dl_size = param_sfo_size;
		if (!http_download_file(piece_urls[0], &param_sfo_data, &param_sfo_dl_size, NULL, param_sfo_offset)) {
			PKG_THROW_ERROR("Unable to download %s for '%s'.\n", "param.sfo", piece_urls[0]);
			goto err;
		}
		//printf("param.sfo size: 0x%" PRIX64 "\n", param_sfo_dl_size);
		if (param_sfo_dl_size != param_sfo_size) {
			PKG_THROW_ERROR("%s size mismatch for '%s'.\n", "param.sfo", piece_urls[0]);
			goto err;
		}
	}

	if (icon0_png_offset > 0 && icon0_png_size > 0) {
		//printf("Downloading %s: %s\n", "icon0.png", piece_urls[0]);
		icon0_png_dl_size = icon0_png_size;
		if (!http_download_file(piece_urls[0], &icon0_png_data, &icon0_png_dl_size, NULL, icon0_png_offset)) {
			PKG_THROW_ERROR("Unable to download %s for '%s'.\n", "icon0.png", piece_urls[0]);
			goto err;
		}
		//printf("icon0.png size: 0x%" PRIX64 "\n", icon0_png_dl_size);
		if (icon0_png_dl_size != icon0_png_size) {
			PKG_THROW_ERROR("%s size mismatch for '%s'.\n", "icon0.png", piece_urls[0]);
			goto err;
		}
	}

	if (bytes_to_hex(pkg_digest_str, sizeof(pkg_digest_str), hdr->digest, sizeof(hdr->digest))) {
		PKG_THROW_ERROR("Unable to convert digest for '%s'.\n", piece_urls[0]);
		goto err;
	}
	if (bytes_to_hex(piece_digest_str, sizeof(piece_digest_str), s_zero_mini_digest, sizeof(s_zero_mini_digest))) {
		PKG_THROW_ERROR("Unable to convert digest for '%s'.\n", piece_urls[0]);
		goto err;
	}

	fp = fopen(ref_pkg_json_path, "wb");
	if (!fp) {
		PKG_THROW_ERROR("fopen(%s) failed: %d\n", ref_pkg_json_path, errno);
		goto err;
	}

	fprintf(fp,
		"{\"originalFileSize\":%" PRIu64 ",\"packageDigest\":\"%s\",\"numberOfSplitFiles\":%" PRIuMAX ",\"pieces\":[",
		BE64(hdr->package_size), pkg_digest_str, (uintmax_t)piece_count
	);

	for (i = 0, offset = 0; i < piece_count; ++i) {
		if (i > 0) {
			//printf("Getting piece information: %s\n", piece_urls[i]);
			if (!http_get_file_size(piece_urls[i], &total_size)) {
				PKG_THROW_ERROR("Unable to get file size for piece '%s'.\n", piece_urls[i]);
				goto err_file_close;
			}
			//printf("Piece size: 0x%" PRIX64 "\n", total_size);
		}

#ifdef ESCAPE_URL
		if (!http_escape_uri(&escaped_url, &escaped_url_size, piece_urls[i])) {
			PKG_THROW_ERROR("Unable to escape URL for piece '%s'.\n", piece_urls[i]);
			goto err_file_close;
		}
#endif

		fprintf(fp,
			"{\"url\":\"%s\",\"fileOffset\":%" PRIu64 ",\"fileSize\":%" PRIu64 ",\"hashValue\":\"%s\"}",
#ifdef ESCAPE_URL
			escaped_url, offset, total_size, piece_digest_str
#else
			piece_urls[i], offset, total_size, piece_digest_str
#endif
		);
		if (i + 1 < piece_count) {
			fputs(",", fp);
		}

		offset += total_size;

#ifdef ESCAPE_URL
		free(escaped_url);
		escaped_url = NULL;
#endif
	}

	fputs("]}", fp);

	if (BE64(hdr->package_size) > 0 && offset != BE64(hdr->package_size)) {
		PKG_THROW_ERROR("Unexpected total file size for '%s'.\n", piece_urls[0]);
		goto err_file_close;
	}

	if (param_sfo_offset > 0 && param_sfo_size > 0) {
		if (!write_file_trunc(param_sfo_path, param_sfo_data, param_sfo_size, NULL, S_IRUSR | S_IWUSR)) {
			PKG_THROW_ERROR("Unable to write %s file for '%s'.\n", "param.sfo", piece_urls[0]);
			goto err_file_close;
		}
	}
	if (icon0_png_offset > 0 && icon0_png_size > 0) {
		if (!write_file_trunc(icon0_png_path, icon0_png_data, icon0_png_size, NULL, S_IRUSR | S_IWUSR)) {
			PKG_THROW_ERROR("Unable to write %s file for '%s'.\n", "icon0.png", piece_urls[0]);
			goto err_file_close;
		}
		if (has_icon) {
			*has_icon = true;
		}
	} else {
		if (has_icon) {
			*has_icon = false;
		}
	}

	if (content_type) {
		*content_type = BE32(hdr->content_type);
	}
	if (package_size) {
		*package_size = BE64(hdr->package_size);
	}

	status = true;

err_file_close:
	if (fp) {
		fclose(fp);
	}

err_file_unlink:
	if (!status) {
		unlink(icon0_png_path);
		unlink(param_sfo_path);
		unlink(ref_pkg_json_path);
	}

err:
#ifdef ESCAPE_URL
	if (escaped_url) {
		free(escaped_url);
	}
#endif

	if (icon0_png_data) {
		free(icon0_png_data);
	}

	if (param_sfo_data) {
		free(param_sfo_data);
	}

	if (entry_table_data) {
		free(entry_table_data);
	}
	if (hdr_data) {
		free(hdr_data);
	}

	return status;
}

#undef PKG_THROW_ERROR

bool pkg_is_patch(struct pkg_header* hdr) {
	unsigned int flags;

	assert(hdr != NULL);

	flags = BE32(hdr->content_flags);

	if (flags & PKG_CONTENT_FLAGS_FIRST_PATCH) {
		return true;
	}
	if (flags & PKG_CONTENT_FLAGS_SUBSEQUENT_PATCH) {
		return true;
	}
	if (flags & PKG_CONTENT_FLAGS_DELTA_PATCH) {
		return true;
	}
	if (flags & PKG_CONTENT_FLAGS_CUMULATIVE_PATCH) {
		return true;
	}

	return false;
}
