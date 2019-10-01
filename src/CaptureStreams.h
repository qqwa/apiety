

#ifndef APIETY2_ENCRYPTEDSTREAM_H
#define APIETY2_ENCRYPTEDSTREAM_H

#include <thread>
#include <chrono>

#define TINS_STATIC
#include <tins/tins.h>
#include <tins/tcp_ip/stream.h>
#include <tins/tcp_ip/stream_follower.h>

#include <spdlog/spdlog.h>
#include "spdlog/fmt/ostr.h"

#include <readerwriterqueue.h>

struct StreamIdentifier {
    size_t id;
    Tins::TCPIP::Stream::timestamp_type creation_time;
    Tins::IPv4Address ip;
    uint16_t port;
    Tins::IPv4Address ip_client;
    uint16_t port_client;
    size_t bytes_recv;
    size_t bytes_send;
    template<typename OStream>
    friend OStream &operator<<(OStream &os, const StreamIdentifier &identifier) {
        return os << identifier.id;
    }
};

enum class Direction {
    ToGameServer,
    FromGameServer,
    ToLoginServer,
    FromLoginServer,
};

template<typename OStream>
OStream &operator<<(OStream &os, const Direction &direction) {
    switch(direction) {
        case Direction::ToGameServer:
            return os << "-> GS";
        case Direction::FromGameServer:
            return os << "<- GS";
        case Direction::ToLoginServer:
            return os << "-> LS";
        case Direction::FromLoginServer:
            return os << "<- LS";
        default:
            return os << "UNKOWN DIRECTION";
    }
}

struct CapturedPacket {
    StreamIdentifier identifier;
    Direction direction;
    std::vector<uint8_t> payload;
};

class CaptureStreams {
public:
    CaptureStreams(moodycamel::BlockingReaderWriterQueue<CapturedPacket> &queue, moodycamel::BlockingReaderWriterQueue<StreamIdentifier> &remove_queue);
    ~CaptureStreams();
    std::thread start_thread();
private:
    size_t count;
    void on_new_stream(Tins::TCPIP::Stream& stream);
    void on_stream_terminated(Tins::TCPIP::Stream& stream, Tins::TCPIP::StreamFollower::TerminationReason reason);
    void on_client_data(Tins::TCPIP::Stream& stream);
    void on_server_data(Tins::TCPIP::Stream& stream);
    void remove_streams(Tins::TCPIP::StreamFollower& follower);

    std::map<Tins::TCPIP::Stream::timestamp_type, StreamIdentifier> stream_identifier;
    moodycamel::BlockingReaderWriterQueue<CapturedPacket> &queue;
    moodycamel::BlockingReaderWriterQueue<StreamIdentifier> &remove_queue;
};


#endif //APIETY2_ENCRYPTEDSTREAM_H
