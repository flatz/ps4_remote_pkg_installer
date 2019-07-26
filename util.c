#include "util.h"

#include <kernel_ex.h>
#include <system_service.h>
#include <ctype.h>

bool get_language_id(int* lang_id) {
	int value;
	int ret;

	ret = sceSystemServiceParamGetInt(SCE_SYSTEM_SERVICE_PARAM_ID_LANG, &value);
	if (ret) {
		EPRINTF("sceSystemServiceParamGetInt failed: 0x%08x\n", ret);
		goto err;
	}

	if (lang_id) {
		*lang_id = value;
	}

	return true;

err:
	return false;
}

int bytes_to_hex(char* buf, size_t buf_size, const void* data, size_t data_size) {
	static const char* digits = "0123456789ABCDEF";
	const uint8_t* in = (const uint8_t*)data;
	char* out = buf;
	uint8_t c;
	size_t i;
	int ret;

	if (!buf || !data) {
		ret = SCE_KERNEL_ERROR_EINVAL;
		goto err;
	}
	if (!buf_size || buf_size < (data_size * 2 + 1)) {
		ret = SCE_KERNEL_ERROR_ENOSPC;
		goto err;
	}
	if (!data_size) {
		*out = '\0';
		goto done;
	}

	for (i = 0; i < data_size; ++i) {
		c = in[i];
		*out++ = digits[c >> 4];
		*out++ = digits[c & 0xF];
	}
	*out++ = '\0';

done:
	ret = 0;

err:
	return ret;
}

bool read_file(const char* path, void** data, uint64_t* size, uint64_t max_size, uint64_t* nread) {
	int fd = -1;
	struct stat info;
	uint64_t file_size, user_size;
	uint64_t size_left, total = 0;
	uint8_t* buf = NULL;
	uint8_t* p;
	ssize_t n;
	bool need_alloc = false;
	bool status = false;
	int ret;

	assert(path != NULL);
	assert(data != NULL);
	assert(size != NULL);

	ret = fd = open(path, O_RDONLY);
	if (ret < 0)
		goto err;

	ret = fstat(fd, &info);
	if (ret < 0)
		goto err;
	file_size = (uint64_t)info.st_size;

	/* User may provide his own buffer. */
	buf = (uint8_t*)*data;

	/* If user size is not specified or it's bigger than real size, then use real size
	   and update user size with its value. */
	user_size = *size;
	if (user_size == (uint64_t)-1)
		user_size = file_size;
	else if (user_size > file_size)
		user_size = file_size;

	/* If max size is set then do additional size check. */
	if (max_size > 0 && max_size != (uint64_t)-1)
		user_size = MIN(user_size, max_size);
	else if (buf) {
		/* If buffer pointer is specified, then we should have max size parameter set. */
		if (buf)
			goto err;
	}

	/* If buffer pointer is null then we need to allocate memory by ourselves. */
	if (!buf) {
		need_alloc = true;
		buf = (uint8_t*)malloc(user_size);
		if (!buf)
			goto err;
	}

	p = buf;
	for (size_left = user_size; size_left > 0;) {
		n = read(fd, p, (size_t)size_left);
		if (n <= 0)
			break; /* status is okay but we need to check num read parameter */
		size_left -= n;
		total += n;
		p += n;
	}

	/* We have read something, so it's okay to fill some information. */
	*data = buf;
	*size = user_size;

	/* Set temporary buffer pointer to null to not free it later (user must do it by himself). */
	buf = NULL;

	status = true;

err:
	if (fd > 0)
		close(fd);

	if (nread)
		*nread = total;

	if (!status) {
		/* If we have failed at beginning then we have no information. */
		*data = NULL;
		*size = 0;

		/* Free memory if we have allocated it before. */
		if (need_alloc) {
			if (buf)
				free(buf);
		}
	}

	return status;
}

bool write_file(const char* path, const void* data, uint64_t size, uint64_t* nwritten, int mode, unsigned int flags) {
	int fd = -1;
	uint64_t size_left, total = 0;
	const uint8_t* buf;
	bool status = false;
	ssize_t n;

	assert(path != NULL);
	assert(size == 0 || data != NULL);

	fd = open(path, O_CREAT | O_WRONLY | flags, mode);
	if (fd < 0)
		goto err;

	if (size > 0) {
		buf = (const uint8_t*)data;
		for (size_left = size; size_left > 0;) {
			n = write(fd, buf, (size_t)size_left);
			if (n <= 0)
				break; /* status is okay but we need to check num written parameter */
			size_left -= n;
			total += n;
			buf += n;
		}
	}

	status = true;

err:
	if (fd > 0)
		close(fd);

	if (nwritten)
		*nwritten = total;

	return status;
}

bool write_file_trunc(const char* path, const void* data, uint64_t size, uint64_t* nwritten, int mode) {
	return write_file(path, data, size, nwritten, mode, O_TRUNC);
}

bool is_file_exists(const char* path) {
	SceKernelStat stat_buf;
	int ret;

	assert(path != NULL);

	ret = sceKernelStat(path, &stat_buf);
	if (ret) {
		return false;
	}

	return SCE_KERNEL_S_ISREG(stat_buf.st_mode);
}

void hexdump(const void* data, size_t size) {
	const uint8_t* p = (const uint8_t*)data;
	const size_t n = 16;
	size_t i, j, k;
	for (i = 0; i < size; i += n) {
		k = (i + n) <= size ? n : (size - i);
		printf("%8p:", (uint8_t*)data + i);
		for (j = 0; j < k; ++j) {
			printf(" %02x", p[i + j]);
		}
		for (j = k; j < n; ++j) {
			printf("   ");
		}
		printf("  ");
		for (j = 0; j < k; ++j) {
			printf("%c", isprint(p[i + j]) ? p[i + j] : '.');
		}
		for (j = k; j < n; ++j) {
			printf(" ");
		}
		printf("\n");
	}
}

bool starts_with(const char* haystack, const char* needle) {
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	for (i = 0; haystack[i] != '\0'; ++i) {
		if (haystack[i] != needle[i]) {
			break;
		}
	}

	return (needle[i] == '\0');
}

bool starts_with_nocase(const char* haystack, const char* needle) {
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	for (i = 0; haystack[i] != '\0'; ++i) {
		if (tolower(haystack[i]) != tolower(needle[i])) {
			break;
		}
	}

	return (needle[i] == '\0');
}

bool ends_with(const char* haystack, const char* needle) {
	ptrdiff_t diff;
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	diff = strlen(haystack) - strlen(needle);
	if (diff < 0) {
		return false;
	}

	for (i = 0; needle[i] != '\0'; ++i) {
		if (needle[i] != haystack[i + diff]) {
			return false;
		}
	}

	return true;
}

bool ends_with_nocase(const char* haystack, const char* needle) {
	ptrdiff_t diff;
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	diff = strlen(haystack) - strlen(needle);
	if (diff < 0) {
		return false;
	}

	for (i = 0; needle[i] != '\0'; ++i) {
		if (tolower(needle[i]) != tolower(haystack[i + diff])) {
			return false;
		}
	}

	return true;
}

static char* rtrim_ex(char* s, int (*check)(int ch)) {
	char* end;
	size_t len;

	assert(s != NULL);
	assert(check != NULL);

	if (*s == '\0')
		return s;

	len = strlen(s);
	for (end = &s[len - 1]; end >= s && check(*end); --end);
	end[1] = '\0';

	return end >= s ? end : NULL;
}

static int check_space(int ch) {
	return isspace(ch);
}

char* rtrim(char* s) {
	return rtrim_ex(s, &check_space);
}

struct timespec* timespec_now(struct timespec* tp) {
	struct timeval tv;
	int ret;

	ret = sceKernelGettimeofday(&tv);
	if (ret) {
		EPRINTF("sceKernelGettimeofday failed: 0x%08X\n", ret);
		return NULL;
	}

	tp->tv_sec = tv.tv_sec;
	tp->tv_nsec = usec_to_nsec(tv.tv_usec);

	return tp;
}

struct timespec* timespec_sub(struct timespec* tp, const struct timespec* a, const struct timespec* b) {
	if ((a->tv_sec < b->tv_sec) || ((a->tv_sec == b->tv_sec) && (a->tv_nsec <= b->tv_nsec))) { /* a <= b? */
		tp->tv_sec = tp->tv_nsec = 0;
	} else { /* a > b? */
		tp->tv_sec = a->tv_sec - b->tv_sec;

		if (a->tv_nsec < b->tv_nsec) {
			tp->tv_nsec = a->tv_nsec + NSEC_PER_SEC - b->tv_nsec;
			--tp->tv_sec; /* borrow a second */
		} else {
			tp->tv_nsec = a->tv_nsec - b->tv_nsec;
		}
	}

	return tp;
}

int timespec_compare(const struct timespec* a, const struct timespec* b) {
	if (a->tv_sec < b->tv_sec)
		return -1;
	if (a->tv_sec > b->tv_sec)
		return 1;
	return a->tv_nsec - b->tv_nsec;
}

