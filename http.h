#pragma once

#include "common.h"

bool http_init(void);
void http_fini(void);

bool http_get_file_size(const char* url, uint64_t* total_size);
bool http_download_file(const char* url, uint8_t** data, uint64_t* data_size, uint64_t* total_size, uint64_t offset);

bool http_escape_uri(char** out, size_t* out_size, const char* in);
bool http_unescape_uri(char** out, size_t* out_size, const char* in);

bool http_escape_json_string(char* out, size_t max_out_size, const char* in);
