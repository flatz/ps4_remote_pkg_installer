#pragma once

#include "common.h"

bool get_language_id(int* lang_id);

int bytes_to_hex(char* buf, size_t buf_size, const void* data, size_t data_size);

bool read_file(const char* path, void** data, uint64_t* size, uint64_t max_size, uint64_t* nread);
bool write_file(const char* path, const void* data, uint64_t size, uint64_t* nwritten, int mode, unsigned int flags);
bool write_file_trunc(const char* path, const void* data, uint64_t size, uint64_t* nwritten, int mode);

bool is_file_exists(const char* path);

void hexdump(const void* data, size_t size);

bool starts_with(const char* haystack, const char* needle);
bool ends_with(const char* haystack, const char* needle);

bool ends_with(const char* haystack, const char* needle);
bool ends_with_nocase(const char* haystack, const char* needle);

char* rtrim(char* s);

#define NSEC_PER_USEC INT64_C(1000)
#define NSEC_PER_MSEC INT64_C(1000000)
#define NSEC_PER_SEC INT64_C(1000000000)

struct timespec* timespec_now(struct timespec* tp);

struct timespec* timespec_sub(struct timespec* tp, const struct timespec* a, const struct timespec* b);

/* a < b: return < 0; a == b: return 0; a > b: return > 0 */
int timespec_compare(const struct timespec* a, const struct timespec* b);

static inline int64_t usec_to_nsec(int64_t x) {
	return NSEC_PER_USEC * x;
}
