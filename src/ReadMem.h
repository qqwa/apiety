#pragma once

#include <thread>
#include <vector>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>

struct KeyPair {
    uint32_t id;
    uint8_t send[32];
    uint8_t send_iv[8];
    uint8_t recv[32];
    uint8_t recv_iv[8];
};

std::vector<KeyPair> search_keys();
int get_pid(DWORD *pid);