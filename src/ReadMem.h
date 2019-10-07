#pragma once

#include <thread>
#include <vector>
#include <readerwriterqueue.h>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>

struct KeyPair {
    uint64_t id;
    uint8_t send[32];
    uint8_t send_iv[8];
    uint8_t recv[32];
    uint8_t recv_iv[8];
};

class ReadMem {
public:
    ReadMem(moodycamel::BlockingReaderWriterQueue<KeyPair> &queue);
    ~ReadMem();
    void start_thread();
    void search_keys();
private:
    int get_pid(DWORD *pid);

    moodycamel::BlockingReaderWriterQueue<KeyPair> &queue;
};