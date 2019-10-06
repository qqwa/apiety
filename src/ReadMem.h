#pragma once

#include <thread>
#include <vector>
#include <readerwriterqueue.h>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>

struct KeyPair {
    char send[64];
    char recv[64];
};

class ReadMem {
public:
    ReadMem(moodycamel::BlockingReaderWriterQueue<KeyPair> &queue);
    ~ReadMem();
    std::thread start_thread();
private:
    void search_keys();
    int get_pid(DWORD *pid);

    moodycamel::BlockingReaderWriterQueue<KeyPair> &queue;
};