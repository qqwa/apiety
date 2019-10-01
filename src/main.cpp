#include <readerwriterqueue.h>
#include "CaptureStreams.h"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <argh.h>


int main(int, char* argv[]) {
    argh::parser cmdl(argv);
    if (cmdl[{ "-d", "--debug" }]) {
        spdlog::set_level(spdlog::level::debug);
    }

    spdlog::set_pattern("[%Y-%M-%d %H:%M:%S] [%^%L%$] %v");
    spdlog::flush_on(spdlog::level::info);

    moodycamel::BlockingReaderWriterQueue<CapturedPacket> queue(1000);
    CaptureStreams captureStreams(queue);
    auto capture_thread = captureStreams.start_thread();

    CapturedPacket item;
    while(true) {
        queue.wait_dequeue(item);

        auto len = item.payload.size();
        auto total = 0;
        switch (item.direction) {
            case Direction::FromLoginServer:
            case Direction::FromGameServer:
                total = item.identifier.bytes_recv;
                break;
            case Direction::ToLoginServer:
            case Direction::ToGameServer:
                total = item.identifier.bytes_send;
                break;
        }

        spdlog::debug("{} {}({:4d} - {:6d}): {:n}", item.identifier, item.direction, len, total, spdlog::to_hex(std::begin(item.payload), std::begin(item.payload) + std::min<size_t>(len, 10ul)));

        item.payload.clear();
    }
}
