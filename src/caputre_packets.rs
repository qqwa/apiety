//! Caputre network traffic

use etherparse::*;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::mpsc;

use pcap::{Capture, Device, Packet};

use crate::packet::{Direction, PoePacket};
use crate::Error;

// listens on all interfaces and searches for packets to/from port 20481, if found shuts down all
// interfaces, but the one that found it
// the remaining interface sends all captured packets with ports 20481 and 6112
pub fn capture_from_interface(sender: mpsc::Sender<Vec<u8>>) -> Result<(), Error> {
    for device in Device::list().unwrap() {
        let device_string = device.name.clone();
        let sender = sender.clone();
        std::thread::Builder::new()
            .name(device_string.clone())
            .spawn(move || {
                let mut cap = Capture::from_device(device)
                    .expect("failed to create capture object from device")
                    .promisc(true)
                    .snaplen(5000)
                    .open()
                    .expect("failed to open capture object");

                cap.filter("tcp port 20481 or tcp port 6112")
                    .expect("capture filter");

                loop {
                    match cap.next() {
                        Ok(packet) => {
                            sender
                                .send(Vec::from(packet.data))
                                .expect("send packet from caputre thread");
                        }
                        Err(pcap::Error::TimeoutExpired) => {}
                        Err(e) => {
                            log::warn!("{:?}", e);
                            break;
                        }
                    }
                }
            })
            .unwrap();
    }

    Ok(())
}

pub fn capture_from_file(
    sender: mpsc::Sender<Vec<u8>>,
    file: &std::path::PathBuf,
) -> Result<(), Error> {
    let mut cap = Capture::from_file(file).expect("failed to open pcap file");
    std::thread::Builder::new()
        .name("pcap_reader".into())
        .spawn(move || {
            cap.filter("tcp port 20481 or tcp port 6112")
                .expect("capture filter");
            //                cap.filter("tcp port 20481").expect("capture filter");

            while let Ok(packet) = cap.next() {
                sender
                    .send(Vec::from(packet.data))
                    .expect("send packet from caputre thread");
            }
        })
        .unwrap();

    Ok(())
}

/// NetPacket is used to reconstruct Tcp Packets from IP Packets
struct NetPacket {
    direction: crate::packet::Direction,
    stream_id: u16,
    payload: Vec<u8>,
}

impl NetPacket {
    pub fn new(payload_slice: &[u8], direction: Direction, stream_id: u16) -> Self {
        let mut payload = Vec::with_capacity(payload_slice.len());
        payload.extend_from_slice(&payload_slice[..]);

        NetPacket {
            direction,
            payload,
            stream_id,
        }
    }

    pub fn append_payload(&mut self, payload: &[u8]) {
        self.payload.extend_from_slice(payload);
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum ConnectionState {
    Handshake(u8),
    Connected,
    Closed,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum StreamChannelState {
    Normal,
    Recover,
    Finished(bool),
    Broken,
}

struct StreamChannel {
    packet_buffer: HashMap<u32, (TcpHeader, Vec<u8>)>,
    count: usize,
    state: StreamChannelState,
    sequence_number: u32,
    next_sequence_number: u32,
    acknowledgment_number: u32,
    current_packet: Option<NetPacket>,
}

impl StreamChannel {
    fn new(tcp: &TcpHeaderSlice) -> StreamChannel {
        StreamChannel {
            packet_buffer: HashMap::new(),
            count: 1,
            state: StreamChannelState::Normal,
            sequence_number: tcp.sequence_number(),
            next_sequence_number: (tcp.sequence_number() + 1) % std::u32::MAX,
            acknowledgment_number: tcp.acknowledgment_number(),
            current_packet: None,
        }
    }

    fn finish_handshake(&mut self, tcp: &TcpHeaderSlice) {
        self.count += 1;
        self.sequence_number = tcp.sequence_number();
        self.next_sequence_number = (tcp.sequence_number()) % std::u32::MAX;
        self.acknowledgment_number = tcp.acknowledgment_number();
    }

    // updates sequence numbers etc...
    fn update(&mut self, packet: &SlicedPacket) -> Vec<NetPacket> {
        let mut packets = Vec::new();
        self.count += 1;
        let tcp = if let Some(TransportSlice::Tcp(value)) = &packet.transport {
            value
        } else {
            log::warn!("Got packet which transport layer was not TCP discarding...");
            panic!("Couldn't get tcp header, this should never happen here");
        };

        self.state = match self.state {
            // everything is normal just check
            StreamChannelState::Normal => {
                if self.next_sequence_number == tcp.sequence_number() {
                    // update internal state
                    self.sequence_number = tcp.sequence_number();
                    self.next_sequence_number =
                        (tcp.sequence_number() + packet.payload.len() as u32) % std::u32::MAX;
                    self.acknowledgment_number = tcp.acknowledgment_number();

                    // construct packet
                    match self.current_packet.as_mut() {
                        Some(net_packet) => {
                            net_packet.append_payload(packet.payload);
                        }
                        None => {
                            let (direction, stream_id) =
                                ports_to_direction(tcp.source_port(), tcp.destination_port());
                            self.current_packet =
                                Some(NetPacket::new(packet.payload, direction, stream_id));
                        }
                    }

                    if tcp.psh() {
                        if let Some(net_packet) = self.current_packet.take() {
                            packets.push(net_packet);
                        } else {
                            log::warn!("Tried to push net_packet even tho it was None");
                        }
                    }

                    if tcp.fin() {
                        self.next_sequence_number = (tcp.sequence_number() + 1) % std::u32::MAX;
                        StreamChannelState::Finished(false)
                    } else {
                        StreamChannelState::Normal
                    }
                } else if self.next_sequence_number > tcp.sequence_number() {
                    log::warn!("Duplicate packet ignoring...");
                    StreamChannelState::Normal
                } else {
                    if packet.payload.len() != 0 {
                        self.packet_buffer.insert(
                            tcp.sequence_number(),
                            (tcp.to_header(), packet.payload.to_owned()),
                        );
                        log::warn!(
                        "[Entering Recover State] Wrong sequence number... expected: {}, got: {}",
                        self.next_sequence_number,
                        tcp.sequence_number()
                        );
                        StreamChannelState::Recover
                    } else {
                        // something is wrong, but as this is a packet without payload just ignore it
                        StreamChannelState::Normal
                    }
                }
            }
            StreamChannelState::Recover => {
                if self.next_sequence_number == tcp.sequence_number() {
                    // found the missing packet
                    let mut last_tcp = tcp.clone();

                    // update internal state
                    self.sequence_number = tcp.sequence_number();
                    self.next_sequence_number =
                        (tcp.sequence_number() + packet.payload.len() as u32) % std::u32::MAX;
                    self.acknowledgment_number = tcp.acknowledgment_number();
                    log::info!(
                        "Found currently missing packet with seq: {}, next: {}",
                        tcp.sequence_number(),
                        self.next_sequence_number
                    );

                    // construct packet
                    match self.current_packet.as_mut() {
                        Some(net_packet) => {
                            net_packet.append_payload(packet.payload);
                        }
                        None => {
                            let (direction, stream_id) =
                                ports_to_direction(tcp.source_port(), tcp.destination_port());
                            self.current_packet =
                                Some(NetPacket::new(packet.payload, direction, stream_id));
                        }
                    }

                    if tcp.psh() {
                        if let Some(net_packet) = self.current_packet.take() {
                            packets.push(net_packet);
                        } else {
                            log::warn!("Tried to push net_packet even tho it was None");
                        }
                    }

                    // try to empty packet buffer
                    while let Some((tcp, payload)) =
                        self.packet_buffer.remove(&self.next_sequence_number)
                    {
                        let mut last_tcp = tcp.clone();
                        // update internal state
                        self.sequence_number = tcp.sequence_number;
                        self.next_sequence_number =
                            (tcp.sequence_number + payload.len() as u32) % std::u32::MAX;
                        self.acknowledgment_number = tcp.acknowledgment_number;
                        log::info!(
                            "Found currently missing packet with seq: {}, next: {}",
                            tcp.sequence_number,
                            self.next_sequence_number
                        );

                        // construct packet
                        match self.current_packet.as_mut() {
                            Some(net_packet) => {
                                net_packet.append_payload(&payload);
                            }
                            None => {
                                let (direction, stream_id) =
                                    ports_to_direction(tcp.source_port, tcp.destination_port);
                                self.current_packet =
                                    Some(NetPacket::new(&payload, direction, stream_id));
                            }
                        }
                    }

                    // still missing packets for full recovery...
                    if self.packet_buffer.is_empty() {
                        log::warn!("[Exiting Recover State]");
                        if last_tcp.fin() {
                            self.next_sequence_number = (tcp.sequence_number() + 1) % std::u32::MAX;
                            StreamChannelState::Finished(false)
                        } else {
                            StreamChannelState::Normal
                        }
                    } else {
                        StreamChannelState::Recover
                    }
                } else if self.next_sequence_number > tcp.sequence_number() {
                    log::warn!("Duplicate packet ignoring...");
                    StreamChannelState::Recover
                } else {
                    // check if we got this packet before inserting into packet buffer, only insert packets with payload
                    if !self.packet_buffer.contains_key(&tcp.sequence_number())
                        && packet.payload.len() != 0
                    {
                        self.packet_buffer.insert(
                            tcp.sequence_number(),
                            (tcp.to_header(), packet.payload.to_owned()),
                        );
                    }
                    StreamChannelState::Recover
                }
            }
            StreamChannelState::Finished(false) => {
                // got acknowledgment?
                if self.next_sequence_number == tcp.sequence_number() {
                    // everything is good got last packet on this stream
                    StreamChannelState::Finished(true)
                } else {
                    StreamChannelState::Broken
                }
            }
            StreamChannelState::Finished(true) => {
                // should not happen?
                StreamChannelState::Broken
            }
            StreamChannelState::Broken => StreamChannelState::Broken,
        };

        packets
    }
}

struct StreamData {
    channel_in: Option<StreamChannel>,
    channel_out: StreamChannel,
    to_out: u16,
    id: u16,
    state: ConnectionState,
}

impl StreamData {
    fn from_tcp_slice(tcp: &TcpHeaderSlice, id: u16) -> Self {
        StreamData {
            channel_in: None,
            channel_out: StreamChannel::new(tcp),
            to_out: tcp.destination_port(),
            id,
            state: ConnectionState::Handshake(0),
        }
    }

    // handles handshake
    fn process(&mut self, packet: SlicedPacket) -> Vec<NetPacket> {
        let mut result = Vec::new();
        let tcp = if let Some(TransportSlice::Tcp(packet)) = &packet.transport {
            packet
        } else {
            log::warn!("Got packet which transport layer was not TCP discarding...");
            return result;
        };
        self.state = match self.state {
            // TODO: move HANDSHAKE to StreamChannel
            ConnectionState::Handshake(step) => {
                match step {
                    0 => {
                        // SYN ACK packet to in
                        if self.to_out == tcp.source_port() {
                            log::trace!("Second step of handshake");
                            let mut channel_in = StreamChannel::new(tcp);

                            if self.channel_out.next_sequence_number == tcp.acknowledgment_number()
                            {
                                self.channel_in = Some(channel_in);

                                ConnectionState::Handshake(step + 1)
                            } else {
                                log::warn!("Wrong acknowledgment number1...");
                                ConnectionState::Closed
                            }
                        } else {
                            log::warn!("Wrong source port...");
                            ConnectionState::Closed
                        }
                    }
                    1 => {
                        // ACK packet to out
                        if self.to_out == tcp.destination_port() {
                            log::trace!("Third step of handshake");
                            if self.channel_in.as_ref().unwrap().next_sequence_number
                                == tcp.acknowledgment_number()
                            {
                                self.channel_out.finish_handshake(&tcp);
                                ConnectionState::Connected
                            } else {
                                log::warn!(
                                    "Wrong acknowledgment number2... expected: {}, got: {}",
                                    self.channel_in.as_ref().unwrap().next_sequence_number,
                                    tcp.acknowledgment_number()
                                );
                                ConnectionState::Closed
                            }
                        } else {
                            log::warn!("Wrong source port...");
                            ConnectionState::Closed
                        }
                    }
                    _ => {
                        log::warn!("Something went wrong on handshake in stream");
                        ConnectionState::Handshake(step)
                    }
                }
            }
            ConnectionState::Connected => {
                // forward packets to correct channel
                if self.to_out == tcp.destination_port() {
                    let mut new_packets = self.channel_out.update(&packet);
                    result.append(&mut new_packets);
                //                    if self.channel_out.state == StreamChannelState::Finished {
                //                        ConnectionState::Broken
                //                    } else {
                //                        ConnectionState::Connected
                //                    }
                } else {
                    let mut new_packets = self.channel_in.as_mut().unwrap().update(&packet);
                    result.append(&mut new_packets);
                    //                    if self.channel_in.as_mut().unwrap().state == StreamChannelState::Finished {
                    //                        ConnectionState::Broken
                    //                    } else {
                    //                        ConnectionState::Connected
                    //                    }
                }
                // check channel state
                let out_state = self.channel_out.state;
                let in_state = self.channel_in.as_ref().unwrap().state;
                if (out_state == StreamChannelState::Finished(true)
                    || out_state == StreamChannelState::Broken)
                    && (in_state == StreamChannelState::Finished(true)
                        || in_state == StreamChannelState::Broken)
                {
                    ConnectionState::Closed
                } else {
                    ConnectionState::Connected
                }
            }
            ConnectionState::Closed => ConnectionState::Closed,
        };
        result
    }
}

pub struct StreamReassembly {
    stream_data: HashMap<u16, StreamData>,
}

impl StreamReassembly {
    pub fn new() -> Self {
        StreamReassembly {
            stream_data: HashMap::new(),
        }
    }

    pub fn process(&mut self, raw_packet: &[u8]) -> Vec<PoePacket> {
        let sliced_packet = SlicedPacket::from_ethernet(&raw_packet);
        let mut packets = Vec::new();
        match sliced_packet {
            Err(e) => log::warn!("Err {:?} --- discarding packet", e),
            Ok(packet) => {
                let packet_clone = packet.clone();
                let ip = if let Some(InternetSlice::Ipv4(value)) = packet.ip {
                    value
                } else {
                    log::warn!("Got packet which transport layer was not TCP discarding...");
                    return packets;
                };
                let tcp = if let Some(TransportSlice::Tcp(value)) = packet.transport {
                    value
                } else {
                    log::warn!("Got packet which transport layer was not TCP discarding...");
                    return packets;
                };

                let (_, stream_id) = ports_to_direction(tcp.source_port(), tcp.destination_port());

                // first packet of handshake
                if tcp.syn() && !tcp.ack() {
                    let old = self.stream_data.remove(&stream_id);
                    if let Some(_) = old {
                        log::warn!("Still had data on old stream with id {0}, when receiving new stream with id {0}", stream_id);
                    }
                    log::info!("Added connection with id {}", stream_id);
                    self.stream_data
                        .insert(stream_id, StreamData::from_tcp_slice(&tcp, stream_id));
                }

                // process packets of a connection, including finishing of the handshake
                if tcp.ack() || tcp.psh() || tcp.fin() {
                    match self.stream_data.get_mut(&stream_id) {
                        Some(stream) => {
                            let new_packets = stream.process(packet_clone);
                            let mut poe_packets = new_packets
                                .into_iter()
                                .map(|net_packet| {
                                    let ip = match net_packet.direction {
                                        Direction::FromLoginserver | Direction::FromGameserver => {
                                            ip.source_addr()
                                        }
                                        Direction::ToLoginserver | Direction::ToGameserver => {
                                            ip.destination_addr()
                                        }
                                    };
                                    PoePacket::new(
                                        &net_packet.payload,
                                        net_packet.direction,
                                        ip,
                                        net_packet.stream_id,
                                    )
                                })
                                .collect();
                            packets.append(&mut poe_packets);
                            if stream.state == ConnectionState::Closed {
                                if self.stream_data.remove(&stream_id).is_some() {
                                    log::info!("Removed connection with id {}", stream_id);
                                }
                            }
                        }
                        None => {
                            // most likly happens after we remove a connection on its first FIN packet
                            // log::warn!("Tried to process packet without existing Stream, probably ACK of FIN?: {:?}", tcp.to_header());
                        }
                    };
                }
            }
        }
        packets
    }
}

// This assumes that the source and destination port are not the same, which should be
// depending on the Ephemeral port range the case.
fn ports_to_direction(source_port: u16, destination_port: u16) -> (Direction, u16) {
    if source_port == 20481 {
        (Direction::FromLoginserver, destination_port)
    } else if destination_port == 20481 {
        (Direction::ToLoginserver, source_port)
    } else if source_port == 6112 {
        (Direction::FromGameserver, destination_port)
    } else if destination_port == 6112 {
        (Direction::ToGameserver, source_port)
    } else {
        // TODO: handle this error better
        panic!("Tried to create PoePacket from unknown port");
    }
}
