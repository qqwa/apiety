#include "CaptureStreams.h"

#include <thread>
#include <spdlog/spdlog.h>

CaptureStreams::CaptureStreams(moodycamel::BlockingReaderWriterQueue<CapturedPacket> &queue) : queue(queue) {
    count = 0;
}

CaptureStreams::~CaptureStreams() {
}

void CaptureStreams::on_client_data(Tins::TCPIP::Stream &stream) {
    auto &identifier = stream_identifier[stream.create_time()];
    auto len = stream.client_payload().size();
    auto &buffer = stream.client_payload();

    Direction direction;
    if (identifier.port == 6112) {
        direction = Direction::ToGameServer;
    } else if (identifier.port = 20481) {
        direction = Direction::ToLoginServer;
    }

    identifier.bytes_send += len;
    CapturedPacket packet = {};
    packet.identifier = identifier;
    packet.direction = direction;
    packet.payload = buffer;
    queue.enqueue(packet);
}

void CaptureStreams::on_server_data(Tins::TCPIP::Stream &stream) {
    auto &identifier = stream_identifier[stream.create_time()];
    auto len = stream.server_payload().size();
    auto &buffer = stream.server_payload();

    Direction direction;
    if (identifier.port == 6112) {
        direction = Direction::FromGameServer;
    } else if (identifier.port = 20481) {
        direction = Direction::FromLoginServer;
    }

    identifier.bytes_recv += len;
    CapturedPacket packet = {};
    packet.identifier = identifier;
    packet.direction = direction;
    packet.payload = buffer;
    queue.enqueue(packet);
}

void CaptureStreams::on_new_stream(Tins::TCPIP::Stream &stream) {
    stream.client_data_callback(std::bind(&CaptureStreams::on_client_data, this, std::placeholders::_1));
    stream.server_data_callback(std::bind(&CaptureStreams::on_server_data, this, std::placeholders::_1));

    StreamIdentifier identifier = {};
    identifier.id = count;
    identifier.creation_time = stream.create_time();
    identifier.ip = stream.server_addr_v4();
    identifier.port = stream.server_port();
    count++;

    stream_identifier.insert({stream.create_time(), identifier});
    spdlog::info("New Stream: id:{} {}:{}", identifier, stream.server_addr_v4().to_string(), stream.server_port());
}

void CaptureStreams::on_stream_terminated(Tins::TCPIP::Stream& stream, Tins::TCPIP::StreamFollower::TerminationReason reason) {
    auto identifier = stream_identifier[stream.create_time()];
    spdlog::info("Stream terminated: id:{} {}:{}", identifier, stream.server_addr_v4().to_string(), stream.server_port());
    stream_identifier.erase(stream.create_time());
}

std::thread CaptureStreams::start_thread() {
    return std::thread([&](){
        Tins::TCPIP::StreamFollower follower;
        follower.stream_keep_alive(std::chrono::seconds(10));
        follower.new_stream_callback(std::bind(&CaptureStreams::on_new_stream, this, std::placeholders::_1));
        follower.stream_termination_callback(std::bind(&CaptureStreams::on_stream_terminated, this, std::placeholders::_1, std::placeholders::_2));

        Tins::SnifferConfiguration config;
        config.set_filter("port 6112 or port 20481");
        config.set_promisc_mode(true);

        Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
        Tins::Sniffer sniffer(iface.name(), config);

        sniffer.sniff_loop([&](Tins::PDU& pdu) {
            follower.process_packet(pdu);
            return true;
        });
    });

}
