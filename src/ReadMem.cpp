#include "ReadMem.h"
#include <spdlog/spdlog.h>
#include <string>

ReadMem::ReadMem(moodycamel::BlockingReaderWriterQueue<KeyPair> &queue) : queue(queue) {}

ReadMem::~ReadMem() {}

std::thread ReadMem::start_thread() {
    return std::thread([&](){
        search_keys();
    });
}

void ReadMem::search_keys() {
    int key_size = 64;
    std::string magic_string = "expand 32-byte k";
    std::vector<int8_t> magic(magic_string.begin(), magic_string.end());
    DWORD pid = 0;
    if (get_pid(&pid)) {
        spdlog::info("Found Path of Exile Process with pid:{}", pid);
        auto handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, true, pid);

        size_t address = 0;
        MEMORY_BASIC_INFORMATION info = {};
        size_t bytes_read = 0;

        std::vector<int8_t> buffer(4092);

        while(true) {
            auto res = VirtualQueryEx(handle, (void*)address, &info, sizeof(MEMORY_BASIC_INFORMATION));
            if (res == 0) {
                spdlog::info("VirtualQueryEx returned 0 with address:{:x}", address);
                break;
            }

            PSAPI_WORKING_SET_EX_INFORMATION page_info = {};
            page_info.VirtualAddress = info.BaseAddress;
            res = QueryWorkingSetEx(handle, &page_info, sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
            if (res == FALSE) {
                auto err = GetLastError();
                spdlog::warn("QueryWorkingSetEx returned false err:{}", err);
            }

            if (page_info.VirtualAttributes.Valid) {
                if (buffer.capacity() < info.RegionSize) {
                    buffer.resize(info.RegionSize);
                    spdlog::debug("Resized ReadProcessMemory buffer to {} bytes",  buffer.size());
                }
                SIZE_T bytes = 0;
                if (! ReadProcessMemory(handle, info.BaseAddress, buffer.data(), info.RegionSize, &bytes)) {
                    spdlog::warn("ReadProcessMemory errored");
                }

                for(int i = 0; i < bytes/16; i++) {
                    if (buffer.size() < (i*16)+ magic.size() || buffer.size() < (i*16) + key_size) {
                        break;
                    }

                    if (magic[0] == buffer[i*16] && magic[1] == buffer[i*16+1] && magic[2] == buffer[i*16+2] && magic[3] == buffer[i*16+3]
//                     && magic[4] == buffer[i*16+4] && magic[5] == buffer[i*16+5] && magic[6] == buffer[i*16+6] && magic[7] == buffer[i*16+7]
//                     && magic[8] == buffer[i*16+8] && magic[9] == buffer[i*16+9] && magic[10] == buffer[i*16+10] && magic[11] == buffer[i*16+11]
//                     && magic[12] == buffer[i*16+12] && magic[13] == buffer[i*16+13] && magic[14] == buffer[i*16+14] && magic[15] == buffer[i*16+15]
                    ) {
                        if (std::equal(magic.begin(), magic.end(), buffer.begin() + (i*16)) && std::equal(magic.begin(), magic.end(), buffer.begin() + (i*16) + 0xc0)) {
                            spdlog::info("Found KeyPair at base:{:x} offset:{:x} size:{:x}", (size_t)info.BaseAddress, (i*16), info.RegionSize);
                            KeyPair pair = {};
                            std::copy(buffer.begin() + (i*16), buffer.begin() + (i*16) + 64, pair.send);
                            std::copy(buffer.begin() + (i*16) + 0xc0, buffer.begin() + (i*16) + 0xc0 + 64, pair.recv);
                            queue.enqueue(pair);
                            i += 0xc0;
                        }
                    }
                }

                bytes_read += bytes;
            }
            address = (size_t)info.BaseAddress + info.RegionSize;
        }
        spdlog::info("Finished scanning memory. Processed {}MB of Memory", bytes_read/1000000);

    } else {
        spdlog::error("Could not find Path of Exile Process");
    }
}

int ReadMem::get_pid(DWORD *pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof entry;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (
             std::wstring(entry.szExeFile) == L"PathOfExile.exe"
             || std::wstring(entry.szExeFile) == L"PathOfExile_x64.exe"
             || std::wstring(entry.szExeFile) == L"PathOfExile_Steam.exe"
             || std::wstring(entry.szExeFile) == L"PathOfExile_x64Steam.exe"
             ) {
                (*pid) = entry.th32ProcessID;
                CloseHandle(snap);
                return 1;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return 0;
}
