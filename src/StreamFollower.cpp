#include "StreamFollower.h"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

StreamFollower::StreamFollower() {
    current_stream = nullptr;
    next_stream = nullptr;
    requested_keys = false;
}

StreamFollower::~StreamFollower() {

}

void StreamFollower::enqueue_packet(CapturedPacket packet) {
    // find correct stream to add packet to, otherwise create new stream and add packet, return as soon as packet was
    // added to a queue
    if (current_stream != nullptr) {
        if (current_stream->identifier == packet.identifier) {
            current_stream->packet_buffer.push(packet);
            return;
        }
    }
    if (next_stream != nullptr) {
        if (next_stream->identifier == packet.identifier) {
            next_stream->packet_buffer.push(packet);
            return;
        }
    }
    if (current_stream == nullptr) {
        spdlog::info("StreamFollower created current stream");
        current_stream = new StreamState;
        current_stream->identifier = packet.identifier;
        current_stream->count_processed_packets_recv = 0;
        current_stream->count_processed_packets_send = 0;
        current_stream->salsa20_recv = nullptr;
        current_stream->salsa20_send = nullptr;
        current_stream->mark_for_removel = false;

        current_stream->packet_buffer.push(packet);
        return;
    }
    if (next_stream == nullptr) {
        spdlog::info("StreamFollower created next stream");
        next_stream = new StreamState;
        next_stream->identifier = packet.identifier;
        next_stream->count_processed_packets_recv = 0;
        next_stream->count_processed_packets_send = 0;
        next_stream->salsa20_recv = nullptr;
        next_stream->salsa20_send = nullptr;
        next_stream->mark_for_removel = false;

        next_stream->packet_buffer.push(packet);
        return;
    }
    spdlog::warn("StreamFollower::enqueue_packet was not able to find queue for a packet");
}

void StreamFollower::remove_stream(StreamIdentifier identifier) {
    if (current_stream != nullptr) {
        if (current_stream->identifier == identifier) {
            spdlog::info("StreamFollower removed current stream");
            delete current_stream;
            current_stream = next_stream;
            next_stream = nullptr;
            return;
        }
    }
    spdlog::warn("StreamFollower::remove_stream tried to remove non existent stream");
}

bool StreamFollower::process_queue() {
    if (current_stream == nullptr || current_stream->mark_for_removel || requested_keys) {
        return false;
    }
    if (!current_stream->packet_buffer.empty()) {
        switch (current_stream->packet_buffer.front().direction) {
            case Direction::FromGameServer:
                return from_gameserver();
            case Direction::ToGameServer:
                return to_gameserver();
            case Direction::FromLoginServer:
                return from_loginserver();
            case Direction::ToLoginServer:
                return to_loginserver();
        }
    }
    return false;
}

bool StreamFollower::from_gameserver() {
    auto packet = current_stream->packet_buffer.front();
    if (current_stream->count_processed_packets_recv == 0) {
        // first to bytes are unencrypted and should be 0x00 0x05, rest needs to be decrypted
        if (packet.payload[0] != 0x00 || packet.payload[1] != 0x05) {
            spdlog::warn("StreamFollower current stream is broken");
            current_stream->mark_for_removel = true;
            return false;
        }
        // rest of packet needs to be decrypted
        salsa20_process(current_stream->salsa20_recv, packet.payload.data()+2, packet.payload.size()-2);

        if (packet.payload[2] != 0x00 || packet.payload[3] != 0x13) {
            spdlog::warn("StreamFollower current stream is broken");
            current_stream->mark_for_removel = true;
            return false;
        }
    } else {
        // packet needs to be decrypted
        salsa20_process(current_stream->salsa20_recv, packet.payload.data(), packet.payload.size());
    }

    if (packet.payload[0] == 0x00 && packet.payload[1] == 0x1a) {
        uint32_t connection_id;
        memcpy(&connection_id, packet.payload.data()+14, sizeof(connection_id));
        connection_id = ntohl(connection_id);

        KeyPair pair = {};
        pair.id = connection_id;
        memcpy(&pair.recv, packet.payload.data()+48, sizeof(pair.recv));
        memcpy(&pair.send, packet.payload.data()+48, sizeof(pair.send));

        memcpy(&pair.send_iv, packet.payload.data()+80, sizeof(pair.send_iv));
        memcpy(&pair.recv_iv, packet.payload.data()+96, sizeof(pair.recv_iv));

        add_key(pair);
        spdlog::info("Gameserver got key for gameserver with id:{}", connection_id);
    }

    spdlog::debug("{} {}({:4d} - {:4d}): {:n}", current_stream->identifier, packet.direction, packet.payload.size(), current_stream->count_processed_packets_recv, spdlog::to_hex(std::begin(packet.payload), std::begin(packet.payload) + std::min<size_t>(packet.payload.size(), 10ul)));
    current_stream->packet_buffer.pop();
    current_stream->count_processed_packets_recv++;
    return true;
}

bool StreamFollower::to_gameserver() {
    auto packet = current_stream->packet_buffer.front();

    if (current_stream->count_processed_packets_send == 0) {
        // unencrypted id should be 0x00 0x03, contains connection id from bytes 2..6 that can be used to identify
        // needed decryption key
        if (packet.payload[0] != 0x00 || packet.payload[1] != 0x03) {
            spdlog::warn("StreamFollower current stream is broken");
            current_stream->mark_for_removel = true;
            return false;
        } else {
            uint32_t connection_id;
            memcpy(&connection_id, packet.payload.data()+2, sizeof(connection_id));
            connection_id = ntohl(connection_id);
            KeyPair pair;
            if (get_key(&pair, connection_id)) {
                current_stream->salsa20_send = salsa20_new(pair.send, pair.send_iv);
                current_stream->salsa20_recv = salsa20_new(pair.recv, pair.recv_iv);
                spdlog::info("New Gameserver connection with connection id {} found key", connection_id);
            } else {
                spdlog::warn("New Gameserver connection with connection id {} could not find key", connection_id);
                spdlog::warn("StreamFollower current stream is broken");
                current_stream->mark_for_removel = true;
                return false;
            }
        }
    } else {
        // packet needs to be decrypted
        salsa20_process(current_stream->salsa20_send, packet.payload.data(), packet.payload.size());
    }
    spdlog::debug("{} {}({:4d} - {:4d}): {:n}", current_stream->identifier, packet.direction, packet.payload.size(), current_stream->count_processed_packets_send, spdlog::to_hex(std::begin(packet.payload), std::begin(packet.payload) + std::min<size_t>(packet.payload.size(), 10ul)));

    current_stream->packet_buffer.pop();
    current_stream->count_processed_packets_send++;
    return true;
}

bool StreamFollower::from_loginserver() {
    auto packet = current_stream->packet_buffer.front();
    if (current_stream->count_processed_packets_recv == 0) {
        // unencrypted id should be 0x00 0x02
        if (packet.payload[0] != 0x00 || packet.payload[1] != 0x02) {
            spdlog::warn("StreamFollower current stream is broken");
            current_stream->mark_for_removel = true;
            return false;
        }
    } else if (current_stream->count_processed_packets_recv == 1) {
        // salsa20 should be set, verify that packet id is 0x00 0x04 after decryption
        if (current_stream->salsa20_recv == nullptr) {
            spdlog::warn("StreamFollower salsa20_recv is not set, stream is broken now");
            current_stream->mark_for_removel = true;
            return false;
        }
        salsa20_process(current_stream->salsa20_recv, packet.payload.data(), packet.payload.size());
    } else {
        salsa20_process(current_stream->salsa20_recv, packet.payload.data(), packet.payload.size());
    }

    if (packet.payload[0] == 0x00 && packet.payload[1] == 0x10) {
        uint32_t connection_id;
        memcpy(&connection_id, packet.payload.data()+10, sizeof(connection_id));
        connection_id = ntohl(connection_id);

        KeyPair pair = {};
        pair.id = connection_id;
        memcpy(&pair.recv, packet.payload.data()+43, sizeof(pair.recv));
        memcpy(&pair.send, packet.payload.data()+43, sizeof(pair.send));

        memcpy(&pair.send_iv, packet.payload.data()+75, sizeof(pair.send_iv));
        memcpy(&pair.recv_iv, packet.payload.data()+91, sizeof(pair.recv_iv));

        add_key(pair);
        spdlog::info("Loginserver got key for gameserver with id:{}", connection_id);
    }

    spdlog::debug("{} {}({:4d} - {:4d}): {:n}", current_stream->identifier, packet.direction, packet.payload.size(), current_stream->count_processed_packets_recv, spdlog::to_hex(std::begin(packet.payload), std::begin(packet.payload) + std::min<size_t>(packet.payload.size(), 10ul)));
    current_stream->packet_buffer.pop();
    current_stream->count_processed_packets_recv++;
    return true;

}

bool StreamFollower::to_loginserver() {
    auto packet = current_stream->packet_buffer.front();
    if (current_stream->count_processed_packets_send == 0) {
        // unencrypted id should be 0x00 0x02
        if (packet.payload[0] != 0x00 || packet.payload[1] != 0x02) {
            spdlog::warn("StreamFollower current stream is broken");
            current_stream->mark_for_removel = true;
            return false;
        }
    } else if (current_stream->count_processed_packets_send == 1) {
        // initialize salsa20, verify that packet id is 0x00 0x03 or 0x00 0x06 after decryption
        KeyPair pair;
        bool found_pair = false;
        uint16_t cipher_id;
        memcpy(&cipher_id, packet.payload.data(), sizeof(cipher_id));
        if (try_keys(cipher_id, htons(0x0003), &pair)) {
            found_pair = true;
            spdlog::info("Found key which statisfies 0x0003 id");
        } else if (try_keys(cipher_id, htons(0x0006), &pair)) {
            found_pair = true;
            spdlog::info("Found key which statisfies 0x0006 id");
        }
        if (!found_pair) {
            spdlog::warn("StreamFollower could not find keypair for stream");
            current_stream->mark_for_removel = true;
            return false;
        }
        current_stream->salsa20_send = salsa20_new(pair.send, pair.send_iv);
        current_stream->salsa20_recv = salsa20_new(pair.recv, pair.recv_iv);
        salsa20_process(current_stream->salsa20_send, packet.payload.data(), packet.payload.size());
    } else {
            salsa20_process(current_stream->salsa20_send, packet.payload.data(), packet.payload.size());
        if (0 < packet.payload.size()) {
        }
    }
    spdlog::debug("{} {}({:4d} - {:4d}): {:n}", current_stream->identifier, packet.direction, packet.payload.size(), current_stream->count_processed_packets_send, spdlog::to_hex(std::begin(packet.payload), std::begin(packet.payload) + std::min<size_t>(packet.payload.size(), 10ul)));
    current_stream->packet_buffer.pop();
    current_stream->count_processed_packets_send++;
    return true;
}

void StreamFollower::add_key(KeyPair key) {
    bool exists = false;
    for(auto &cur_key : keys) {
        if (cur_key.id == key.id) {
            exists = true;
        }
    }
    if (!exists) {
        spdlog::debug("added key with id:{}", key.id);
        keys.push_back(key);
    }
}

bool StreamFollower::get_key(KeyPair *key, uint32_t id) {
    for(auto &cur_key : keys) {
        if (cur_key.id == id) {
            *key = cur_key;
            return true;
        }
    }
    return false;
}

bool StreamFollower::try_keys(uint16_t cipher, uint16_t expected, KeyPair *pair) {
    for(auto& key : keys) {
        if (try_key(cipher, expected, key)) {
            *pair = key;
            return true;
        }
    }
    // search process memory for keys and try again
    auto process_keys = search_keys();
    for(auto& key : process_keys) {
        if (try_key(cipher, expected, key)) {
            *pair = key;
            return true;
        }
    }
    return false;
}

bool StreamFollower::try_key(uint16_t cipher, uint16_t expected, KeyPair pair) {
    auto salsa20 = salsa20_new(pair.send, pair.send_iv);
    uint16_t data = cipher;
    salsa20_process(salsa20, reinterpret_cast<uint8_t *>(&data), sizeof(data));
    salsa20_free(salsa20);

    if(data == expected) {
        return true;
    } else {
        spdlog::warn("data = {}, expeted = {}", data, expected);
        return false;
    }
}
