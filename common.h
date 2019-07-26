#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include "syscalls.h"

#define STRINGIFY(x) #x
#define STRINGIFY_DEEP(x) STRINGIFY(x)

#define JOIN_HELPER(x, y) x##y
#define JOIN(x, y) JOIN_HELPER(x, y)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define ALIGN_UP(x, alignment) (((x) + ((alignment) - 1)) & ~((alignment) - 1))
#define ALIGN_DOWN(x, alignment) ((x) & ~((alignment) - 1))

#define UNUSED(x) (void)(x)

#if 1
#	define EPRINTF(msg, ...) printf("Error at %s:%s(%d): " msg, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#	define EPRINTF(msg, ...)
#endif

#define SWAP16(x) \
	((uint16_t)( \
		(((uint16_t)(x) & UINT16_C(0x00FF)) << 8) | \
		(((uint16_t)(x) & UINT16_C(0xFF00)) >> 8) \
	))

#define SWAP32(x) \
	((uint32_t)( \
		(((uint32_t)(x) & UINT32_C(0x000000FF)) << 24) | \
		(((uint32_t)(x) & UINT32_C(0x0000FF00)) <<  8) | \
		(((uint32_t)(x) & UINT32_C(0x00FF0000)) >>  8) | \
		(((uint32_t)(x) & UINT32_C(0xFF000000)) >> 24) \
	))

#define SWAP64(x) \
	((uint64_t)( \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0x00000000000000FF)) << 56) | \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0x000000000000FF00)) << 40) | \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0x0000000000FF0000)) << 24) | \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0x00000000FF000000)) <<  8) | \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0x000000FF00000000)) >>  8) | \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0x0000FF0000000000)) >> 24) | \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0x00FF000000000000)) >> 40) | \
		(uint64_t)(((uint64_t)(x) & UINT64_C(0xFF00000000000000)) >> 56) \
	))

#define LE16(x) (x)
#define LE32(x) (x)
#define LE64(x) (x)

#define BE16(x) SWAP16(x)
#define BE32(x) SWAP32(x)
#define BE64(x) SWAP64(x)

#ifndef MIN
#	define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#	define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define TYPE_PAD(size) char JOIN(_pad_, __COUNTER__)[size]
#define TYPE_VARIADIC_BEGIN(name) name { union {
#define TYPE_BEGIN(name, size) name { union { TYPE_PAD(size)
#define TYPE_END(...) }; } __VA_ARGS__
#define TYPE_FIELD(field, offset) struct { TYPE_PAD(offset); field; }

#define TYPE_CHECK_SIZE(name, size) \
	_Static_assert(sizeof(name) == (size), "Size of " #name " != " #size)

#define TYPE_CHECK_FIELD_OFFSET(name, member, offset) \
	_Static_assert(offsetof(name, member) == (offset), "Offset of " #name "." #member " != " #offset)

#define TYPE_CHECK_FIELD_SIZE(name, member, size) \
	_Static_assert(sizeof(((name*)0)->member) == (size), "Size of " #name "." #member " != " #size)

enum {
	SUPERCALL_NULL,
	SUPERCALL_PEEK_POKE,
	SUPERCALL_GET_MEMORY_LAYOUT,
	SUPERCALL_SET_AUTH_INFO,
	SUPERCALL_GATE,
	SUPERCALL_DLSYM,
};
