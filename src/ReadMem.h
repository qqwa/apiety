#pragma once

#include <thread>
#include <vector>
#ifdef _WIN32
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#endif

struct KeyPair {
    uint32_t id;
    uint8_t send[32];
    uint8_t send_iv[8];
    uint8_t recv[32];
    uint8_t recv_iv[8];
};

std::vector<KeyPair> search_keys();
#ifdef __linux__
int get_pid(uint64_t *pid);
#elif _WIN32
int get_pid(DWORD *pid);
#endif