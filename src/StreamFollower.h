#pragma once

#include <vector>
#include <queue>

#include "CaptureStreams.h"
#include "ReadMem.h"
//struct KeyPair;
//struct CapturedPacket;


struct StreamState {
    StreamIdentifier identifier;
    std::queue<CapturedPacket> packet_buffer;
    void * salsa20_send;
    void * salsa20_recv;
    size_t count_processed_packets_send;
    size_t count_processed_packets_recv;
    bool mark_for_removel;
};

class StreamFollower {
public:
    StreamFollower();
    ~StreamFollower();
    void add_key(KeyPair);
    void enqueue_packet(CapturedPacket packet);
    void remove_stream(StreamIdentifier identifier);
    bool process_queue();
private:
    bool from_gameserver();
    bool to_gameserver();
    bool from_loginserver();
    bool to_loginserver();
    std::vector<KeyPair> keys;
    StreamState *current_stream;
    StreamState *next_stream;
    bool requested_keys;
};
