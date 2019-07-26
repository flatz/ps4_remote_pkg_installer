#include "sfo.h"
#include "util.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <utlist.h>

#define SFO_MAGIC "\0PSF"

#define SIZEOF_SFO_HEADER 0x14

TYPE_BEGIN(struct sfo_header, SIZEOF_SFO_HEADER);
	TYPE_FIELD(char magic[4], 0x00);
	TYPE_FIELD(uint32_t version, 0x04);
	TYPE_FIELD(uint32_t key_table_offset, 0x08);
	TYPE_FIELD(uint32_t value_table_offset, 0x0C);
	TYPE_FIELD(uint32_t entry_count, 0x10);
TYPE_END();
TYPE_CHECK_SIZE(struct sfo_header, SIZEOF_SFO_HEADER);

#define SIZEOF_SFO_TABLE_ENTRY 0x10

TYPE_BEGIN(struct sfo_table_entry, SIZEOF_SFO_TABLE_ENTRY);
	TYPE_FIELD(uint16_t key_offset, 0x00);
	TYPE_FIELD(uint16_t format, 0x02);
	TYPE_FIELD(uint32_t size, 0x04);
	TYPE_FIELD(uint32_t max_size, 0x08);
	TYPE_FIELD(uint32_t value_offset, 0x0C);
TYPE_END();
TYPE_CHECK_SIZE(struct sfo_table_entry, SIZEOF_SFO_TABLE_ENTRY);

struct sfo* sfo_alloc(void) {
	struct sfo* sfo = NULL;

	sfo = (struct sfo*)malloc(sizeof(*sfo));
	if (!sfo)
		goto error;
	memset(sfo, 0, sizeof(*sfo));

	return sfo;

error:
	if (sfo)
		free(sfo);

	return NULL;
}

void sfo_free(struct sfo* sfo) {
	struct sfo_entry* entry;
	struct sfo_entry* tmp;

	if (!sfo)
		return;

	DL_FOREACH_SAFE(sfo->entries, entry, tmp) {
		DL_DELETE(sfo->entries, entry);

		if (entry->key)
			free(entry->key);

		if (entry->value)
			free(entry->value);

		free(entry);
	}

	free(sfo);
}

bool sfo_load_from_file(struct sfo* sfo, const char* file_path) {
	struct stat stats;
	uint8_t* data = NULL;
	size_t data_size;
	ssize_t nread;
	int fd = -1;
	bool status = false;
	int ret;

	assert(sfo != NULL);
	assert(file_path != NULL);

	fd = open(file_path, O_RDONLY);
	if (fd < 0) {
		EPRINTF("Unable to open file.\n");
		goto err;
	}

	ret = fstat(fd, &stats);
	if (ret < 0) {
		EPRINTF("Unable to get file information.\n");
		goto err;
	}
	data_size = (size_t)stats.st_size;

	data = (uint8_t*)malloc(data_size);
	if (!data) {
		EPRINTF("Unable to allocate memory of 0x%" PRIuMAX " bytes.\n", (uintmax_t)data_size);
		goto err;
	}

	nread = read(fd, data, data_size);
	if (nread < 0) {
		EPRINTF("Unable to read file.\n");
		goto err;
	}
	if ((size_t)nread != data_size) {
		EPRINTF("Insufficient data read.\n");
		goto err;
	}

	if (!sfo_load_from_memory(sfo, data, data_size)) {
		EPRINTF("Unable to load system file object.\n");
		goto err;
	}

	status = true;

err:
	if (data) {
		free(data);
	}

	if (fd > 0) {
		close(fd);
	}

	return status;
}

bool sfo_load_from_memory(struct sfo* sfo, const void* data, size_t data_size) {
	struct sfo_header* hdr;
	struct sfo_table_entry* entry_table;
	struct sfo_table_entry* entry;
	struct sfo_entry* entries = NULL;
	struct sfo_entry* new_entry = NULL;
	const char* key_table;
	const uint8_t* value_table;
	size_t entry_count, i;
	bool status = false;

	assert(sfo != NULL);
	assert(data != NULL);

	if (data_size < sizeof(*hdr)) {
		EPRINTF("Insufficient data.\n");
		goto err;
	}

	hdr = (struct sfo_header*)data;
	if (memcmp(hdr->magic, SFO_MAGIC, sizeof(hdr->magic)) != 0) {
		EPRINTF("Invalid system file object format.\n");
		goto err;
	}

	entry_table = (struct sfo_table_entry*)(data + sizeof(*hdr));
	entry_count = LE32(hdr->entry_count);
	if (data_size < sizeof(*hdr) + entry_count * sizeof(*entry_table)) {
		EPRINTF("Insufficient data.\n");
		goto err;
	}

	key_table = (const char*)data + LE32(hdr->key_table_offset);
	value_table = (const uint8_t*)data + LE32(hdr->value_table_offset);

	for (i = 0; i < entry_count; ++i) {
		entry = entry_table + i;

		new_entry = (struct sfo_entry*)malloc(sizeof(*new_entry));
		if (!new_entry) {
			EPRINTF("Unable to allocate memory for entry.\n");
			goto err;
		}
		memset(new_entry, 0, sizeof(*new_entry));

		new_entry->format = (enum sfo_value_format)LE16(entry->format);

		new_entry->size = LE32(entry->size);
		new_entry->area = LE32(entry->max_size);
		if (new_entry->area < new_entry->size) {
			EPRINTF("Unexpected entry sizes.\n");
			goto err;
		}

		new_entry->key = strdup(key_table + LE16(entry->key_offset));
		if (!new_entry->key) {
			EPRINTF("Unable to allocate memory for entry key.\n");
			goto err;
		}

		new_entry->value = (uint8_t*)malloc(new_entry->area);
		if (!new_entry->value) {
			EPRINTF("Unable to allocate memory for entry value.\n");
			goto err;
		}
		memset(new_entry->value, 0, new_entry->area);
		memcpy(new_entry->value, value_table + LE16(entry->value_offset), new_entry->size);

		DL_APPEND(entries, new_entry);
	}
	new_entry = NULL;

	sfo->entries = entries;

	status = true;

err:
	if (new_entry) {
		if (new_entry->key) {
			free(new_entry->key);
		}

		if (new_entry->value) {
			free(new_entry->value);
		}

		free(new_entry);
	}

	return status;
}

struct sfo_entry* sfo_find_entry(struct sfo* sfo, const char* key) {
	struct sfo_entry* entry;

	assert(sfo != NULL);
	assert(key != NULL);

	DL_FOREACH(sfo->entries, entry) {
		if (strcmp(entry->key, key) == 0) {
			return entry;
		}
	}

	return NULL;
}
