#include "ReadMem.h"
#include <spdlog/spdlog.h>
#include <string>

std::vector<KeyPair> search_keys() {
    std::vector<KeyPair> result;
    int key_size = 64;
    std::string magic_string = "expand 32-byte k";
    std::vector<uint8_t> magic(magic_string.begin(), magic_string.end());
    #ifdef __linux__
    uint64_t pid = 0;
    #elif _WIN32
    DWORD pid = 0;
    #endif

    if (get_pid(&pid)) {
        spdlog::info("Found Path of Exile Process with pid:{}", pid);
        #ifdef __linux__

        #elif _WIN32
        auto handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, true, pid);

        size_t address = 0;
        MEMORY_BASIC_INFORMATION info = {};
        size_t bytes_read = 0;

        std::vector<uint8_t> buffer(4092);

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
                    ) {
                        if (std::equal(magic.begin(), magic.end(), buffer.begin() + (i*16)) && std::equal(magic.begin(), magic.end(), buffer.begin() + (i*16) + 0xc0)) {
                            spdlog::info("Found KeyPair at base:{:x} offset:{:x} size:{:x}", (size_t)info.BaseAddress, (i*16), info.RegionSize);
                            KeyPair pair = {};
                            pair.id = 0;
                            uint8_t *sbp = (uint8_t *)&buffer[i*16 + 16];
                            std::copy(sbp+ 9*4, sbp+ 9*4+4, &pair.send[0*4]);
                            std::copy(sbp+ 6*4, sbp+ 6*4+4, &pair.send[1*4]);
                            std::copy(sbp+ 3*4, sbp+ 3*4+4, &pair.send[2*4]);
                            std::copy(sbp+ 0*4, sbp+ 0*4+4, &pair.send[3*4]);
                            std::copy(sbp+11*4, sbp+11*4+4, &pair.send[4*4]);
                            std::copy(sbp+ 8*4, sbp+ 8*4+4, &pair.send[5*4]);
                            std::copy(sbp+ 5*4, sbp+ 5*4+4, &pair.send[6*4]);
                            std::copy(sbp+ 2*4, sbp+ 2*4+4, &pair.send[7*4]);

                            std::copy(sbp+10*4, sbp+10*4+4, &pair.send_iv[0]);
                            std::copy(sbp+ 7*4, sbp+ 7*4+4, &pair.send_iv[4]);

                            uint8_t *rbp = (uint8_t *)&buffer[i*16 + 16 + 0xc0];
                            std::copy(rbp+ 9*4, rbp+ 9*4+4, &pair.recv[0*4]);
                            std::copy(rbp+ 6*4, rbp+ 6*4+4, &pair.recv[1*4]);
                            std::copy(rbp+ 3*4, rbp+ 3*4+4, &pair.recv[2*4]);
                            std::copy(rbp+ 0*4, rbp+ 0*4+4, &pair.recv[3*4]);
                            std::copy(rbp+11*4, rbp+11*4+4, &pair.recv[4*4]);
                            std::copy(rbp+ 8*4, rbp+ 8*4+4, &pair.recv[5*4]);
                            std::copy(rbp+ 5*4, rbp+ 5*4+4, &pair.recv[6*4]);
                            std::copy(rbp+ 2*4, rbp+ 2*4+4, &pair.recv[7*4]);

                            std::copy(rbp+10*4, rbp+10*4+4, &pair.recv_iv[0]);
                            std::copy(rbp+ 7*4, rbp+ 7*4+4, &pair.recv_iv[4]);

                            result.push_back(pair);
                            i += 0xc0;
                        }
                    }
                }

                bytes_read += bytes;
            }
            address = (size_t)info.BaseAddress + info.RegionSize;
        }
        spdlog::info("Finished scanning memory. Processed {}MB of Memory", bytes_read/1000000);
        #endif
    } else {
        spdlog::error("Could not find Path of Exile Process");
    }
    return result;
}


#ifdef __linux__

int get_pid(uint64_t *pid) {
    spdlog::info("get pid linux called");

    *pid = 5;

    return 0;
}

#elif _WIN32

int get_pid(DWORD *pid) {
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

#endif
