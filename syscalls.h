#pragma once

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_unmount 22
#define	SYS_getdents 272
#define	SYS_nmount 378
#define SYS_supercall 394
#define SYS_gain_privileges 410
#define SYS_dynlib_get_info 593
#define SYS_dynlib_get_info_ex 608

int syscall(int num, ...);

#ifdef __cplusplus
}
#endif
