#pragma once

#include "common.h"

#include <net.h>

bool net_init(void);
bool net_is_initialized(void);
int net_get_mem_id(void);
void net_fini(void);

int net_get_ipv4(char* buf, size_t buf_size);

int net_send_all(SceNetId sock_id, const void* data, size_t size, size_t* sent);
int net_recv_all(SceNetId sock_id, void* data, size_t size, size_t* received);
