#pragma once

#include "common.h"

bool server_start(const char* ip_address, int port, const char* work_dir);
bool server_listen(void);
void server_stop(void);
