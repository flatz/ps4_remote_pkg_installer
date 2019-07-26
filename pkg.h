#pragma once

#include "common.h"

enum pkg_entry_id {
	PKG_ENTRY_ID__PARAM_SFO = 0x1000,
	PKG_ENTRY_ID__ICON0_PNG = 0x1200,
};

enum pkg_content_type {
	PKG_CONTENT_TYPE_GD = 0x1A, /* pkg_ps4_app, pkg_ps4_patch, pkg_ps4_remaster */
	PKG_CONTENT_TYPE_AC = 0x1B, /* pkg_ps4_ac_data, pkg_ps4_sf_theme, pkg_ps4_theme */
	PKG_CONTENT_TYPE_AL = 0x1C, /* pkg_ps4_ac_nodata */
	PKG_CONTENT_TYPE_DP = 0x1E, /* pkg_ps4_delta_patch */
};

#define PKG_TITLE_ID_SIZE 0x9
#define PKG_SERVICE_ID_SIZE 0x13
#define PKG_CONTENT_ID_SIZE 0x24
#define PKG_LABEL_SIZE 0x10
#define PKG_DIGEST_SIZE 0x20
#define PKG_MINI_DIGEST_SIZE 0x14

#define SIZEOF_PKG_HEADER 0x2000

TYPE_BEGIN(struct pkg_header, SIZEOF_PKG_HEADER);
	TYPE_FIELD(uint8_t magic[4], 0x00);
	TYPE_FIELD(uint32_t entry_count, 0x10);
	TYPE_FIELD(uint16_t sc_entry_count, 0x14);
	TYPE_FIELD(uint32_t entry_table_offset, 0x18);
	TYPE_FIELD(char content_id[PKG_CONTENT_ID_SIZE + 1], 0x40);
	TYPE_FIELD(uint32_t content_type, 0x74);
	TYPE_FIELD(uint32_t content_flags, 0x78);
#		define PKG_CONTENT_FLAGS_FIRST_PATCH      0x00100000
#		define PKG_CONTENT_FLAGS_PATCHGO          0x00200000
#		define PKG_CONTENT_FLAGS_REMASTER         0x00400000
#		define PKG_CONTENT_FLAGS_PS_CLOUD         0x00800000
#		define PKG_CONTENT_FLAGS_GD_AC            0x02000000
#		define PKG_CONTENT_FLAGS_NON_GAME         0x04000000
#		define PKG_CONTENT_FLAGS_0x8000000        0x08000000 /* has data? */
#		define PKG_CONTENT_FLAGS_SUBSEQUENT_PATCH 0x40000000
#		define PKG_CONTENT_FLAGS_DELTA_PATCH      0x41000000
#		define PKG_CONTENT_FLAGS_CUMULATIVE_PATCH 0x60000000
	TYPE_FIELD(uint64_t package_size, 0x430);
	TYPE_FIELD(uint8_t digest[PKG_DIGEST_SIZE], 0xFE0);
TYPE_END();
TYPE_CHECK_SIZE(struct pkg_header, SIZEOF_PKG_HEADER);

#define SIZEOF_PKG_TABLE_ENTRY 0x20

TYPE_BEGIN(struct pkg_table_entry, SIZEOF_PKG_TABLE_ENTRY);
	TYPE_FIELD(uint32_t id, 0x00); // enum pkg_entry_id
	TYPE_FIELD(uint32_t offset, 0x10);
	TYPE_FIELD(uint32_t size, 0x14);
TYPE_END();
TYPE_CHECK_SIZE(struct pkg_table_entry, SIZEOF_PKG_TABLE_ENTRY);

struct pkg_content_info {
	char content_id[PKG_CONTENT_ID_SIZE + 1];
	char service_id[PKG_SERVICE_ID_SIZE + 1];
	char title_id[PKG_TITLE_ID_SIZE + 1];
	char label[PKG_LABEL_SIZE + 1];
};

bool pkg_parse_content_id(const char* content_id, struct pkg_content_info* info);

char** pkg_extract_piece_urls_from_ref_pkg_json(const char* url, size_t* piece_count);

bool pkg_setup_prerequisites(char** piece_urls, size_t piece_count, const char* ref_pkg_json_path, const char* param_sfo_path, const char* icon0_png_path, enum pkg_content_type* content_type, uint64_t* package_size, bool* is_patch, bool* has_icon, char* error_buf, size_t error_buf_size);

bool pkg_is_patch(struct pkg_header* hdr);
