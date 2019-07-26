#pragma once

#include "common.h"

enum sfo_value_format {
	SFO_FORMAT_STRING_SPECIAL = 0x4,
	SFO_FORMAT_STRING = 0x204,
	SFO_FORMAT_UINT32 = 0x404,
};

struct sfo_entry {
	char* key;
	size_t size;
	size_t area;
	void* value;
	enum sfo_value_format format;
	struct sfo_entry* next;
	struct sfo_entry* prev;
};

struct sfo {
	struct sfo_entry* entries;
};

struct sfo* sfo_alloc(void);
void sfo_free(struct sfo* sfo);

bool sfo_load_from_file(struct sfo* sfo, const char* file_path);
bool sfo_load_from_memory(struct sfo* sfo, const void* data, size_t data_size);

struct sfo_entry* sfo_find_entry(struct sfo* sfo, const char* key);
