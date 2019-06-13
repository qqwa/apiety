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

use std::cmp::Ordering;

/// implements RFC 1982 for u32 bit SerialNumbers
#[derive(Eq)]
struct SerialNumber(u32);

impl Ord for SerialNumber {
    fn cmp(&self, rhs: &Self) -> Ordering {
        if self.0 == rhs.0 {
            return Ordering::Equal;
        }
        if (self.0 < rhs.0 && rhs.0 - self.0 < 2147483648)
            || (self.0 > rhs.0 && self.0 - rhs.0 > 2147483648)
        {
            return Ordering::Less;
        } else {
            return Ordering::Greater;
        }
    }
}
impl PartialOrd for SerialNumber {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}
impl PartialEq for SerialNumber {
    fn eq(&self, rhs: &Self) -> bool {
        self.0 == rhs.0
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct StreamIdentifier {
    pub(crate) source_ip: std::net::Ipv4Addr,
    pub(crate) dest_ip: std::net::Ipv4Addr,
    pub(crate) source_port: u16,
    pub(crate) dest_port: u16,
}

impl StreamIdentifier {
    pub fn new(
        source_ip: std::net::Ipv4Addr,
        dest_ip: std::net::Ipv4Addr,
        source_port: u16,
        dest_port: u16,
    ) -> Self {
        StreamIdentifier {
            source_ip,
            dest_ip,
            source_port,
            dest_port,
        }
    }

    pub fn from_sliced_packet(packet: &SlicedPacket) -> Option<Self> {
        let ip = if let Some(InternetSlice::Ipv4(value)) = &packet.ip {
            value
        } else {
            return None;
        };
        let tcp = if let Some(TransportSlice::Tcp(value)) = &packet.transport {
            value
        } else {
            return None;
        };
        Some(StreamIdentifier {
            source_ip: ip.source_addr(),
            dest_ip: ip.destination_addr(),
            source_port: tcp.source_port(),
            dest_port: tcp.destination_port(),
        })
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum StreamState {
    Initial,
    Sent_SYN,
    Established,
    Sent_FIN,
    Finished,
    Sent_RST,
    Broken,
}

impl StreamState {
    fn update(&self, tcp: &TcpHeaderSlice) -> StreamState {
        use StreamState::*;

        if tcp.syn() && tcp.ack() {
            return Established;
        }
        if tcp.fin() {
            return Sent_FIN;
        }
        if tcp.syn() {
            return Sent_SYN;
        }
        if tcp.rst() {
            return Sent_RST;
        }

        if *self == Sent_SYN && tcp.ack() {
            return Established;
        }
        if *self == Sent_FIN && tcp.ack() {
            return Finished;
        }

        return *self;
    }
}

struct Fragment {
    tcp: TcpHeader,
    payload: Vec<u8>,
}

struct Stream {
    identifier: StreamIdentifier,
    fragments: HashMap<u32, Fragment>,
    state: StreamState,
    sequence_number: SerialNumber,
    buffer: Vec<u8>,
    sender: mpsc::Sender<PoePacket>,
}

impl Stream {
    fn new(identifier: StreamIdentifier, sender: mpsc::Sender<PoePacket>) -> Self {
        Stream {
            identifier,
            fragments: HashMap::new(),
            state: StreamState::Initial,
            sequence_number: SerialNumber(0),
            buffer: Vec::new(),
            sender,
        }
    }

    fn process(&mut self, packet: SlicedPacket) {
        if self.state == StreamState::Broken {
            return;
        }

        let ip = if let Some(InternetSlice::Ipv4(value)) = &packet.ip {
            value
        } else {
            self.state = StreamState::Broken;
            return;
        };
        let tcp = if let Some(TransportSlice::Tcp(value)) = &packet.transport {
            value
        } else {
            self.state = StreamState::Broken;
            return;
        };

        if tcp.checksum()
            != tcp
                .calc_checksum_ipv4(&ip, packet.payload)
                .expect("calc checksum")
        {
            log::warn!("{:?} Wrong checksum discard...", self.identifier);
            return;
        }

        // TODO: we may change to Finished state even if some data is transferred if the FIN packet arrived out of order
        let old_state = self.state;
        self.state = old_state.update(&tcp);

        if old_state != self.state {
            log::info!(
                "{:?} state change: {:?}->{:?}",
                self.identifier,
                old_state,
                self.state
            );
        }

        if (old_state == StreamState::Sent_SYN || old_state == StreamState::Initial)
            && self.state == StreamState::Established
            && tcp.ack()
        {
            self.sequence_number = SerialNumber(tcp.sequence_number());
            if tcp.syn() && tcp.ack() {
                self.sequence_number.0 += 1;
            }
            log::info!(
                "Established stream with sequence number: {}",
                tcp.sequence_number()
            );
        }

        //packet potentielly contains data
        if let StreamState::Established = old_state {
            // no new data
            if SerialNumber(tcp.sequence_number() + packet.payload.len() as u32)
                < self.sequence_number
            {
                return;
            }
            let mut tcp = tcp.to_header();
            let mut payload = packet.payload.to_vec();
            // sequence number is lower then the one we currently have, so we don't need all data
            // of this chunk
            if SerialNumber(tcp.sequence_number) < self.sequence_number {
                // correct fragment to only contain new data, including tcp header and payload vector..
                let diff = self.sequence_number.0 - tcp.sequence_number;
                tcp.sequence_number = self.sequence_number.0;
                payload.drain((0..diff as usize));
            }
            // check if we can insert fragment
            match self.fragments.get_mut(&tcp.sequence_number) {
                Some(fragment) => {
                    if fragment.payload.len() < payload.len() {
                        fragment.payload = payload;
                        fragment.tcp = tcp;
                    }
                }
                None => {
                    self.fragments
                        .insert(tcp.sequence_number, Fragment { tcp, payload });
                }
            }
        }

        // new packet may have filled the missing data, check if can get data from out of order packets
        self.process_fragments();
    }

    fn process_fragments(&mut self) {
        let mut sequence_number = SerialNumber(0);
        let mut buffer = Vec::new();
        std::mem::swap(&mut self.sequence_number, &mut sequence_number);
        std::mem::swap(&mut self.buffer, &mut buffer);

        let sender = &self.sender;
        let identifier = &self.identifier;

        self.fragments.retain(|&key, item| {
            if SerialNumber(key) > sequence_number {
                // too large we are missing data
                return true;
            }
            if SerialNumber(key) < sequence_number {
                // sequence number is smaller, check if it contains usable data
                if sequence_number < SerialNumber(key + item.payload.len() as u32) {
                    item.payload.drain((0..(sequence_number.0 - key) as usize));
                    sequence_number.0 += item.payload.len() as u32;
                    buffer.append(&mut item.payload);
                } else {
                    return false;
                }
            } else {
                // sequence numbers are equal simly add this packet
                sequence_number.0 += item.payload.len() as u32;
                buffer.append(&mut item.payload)
            }
            if item.tcp.psh && buffer.len() != 0 {
                // TODO: push buffer
                //                log::info!("Would have pushed {} bytes", buffer.len());
                let packet = PoePacket::new(&buffer[..], *identifier);
                sender.send(packet).expect("failed to send NetPacket");
                buffer.drain((..));
            }
            // remove from map
            false
        });

        std::mem::swap(&mut self.sequence_number, &mut sequence_number);
        std::mem::swap(&mut self.buffer, &mut buffer);
    }
}

pub struct StreamReassembly {
    stream_data: HashMap<StreamIdentifier, Stream>,
    sender: mpsc::Sender<PoePacket>,
}

impl StreamReassembly {
    pub fn new(sender: mpsc::Sender<PoePacket>) -> Self {
        StreamReassembly {
            stream_data: HashMap::new(),
            sender,
        }
    }

    pub fn process(&mut self, raw_packet: &[u8]) {
        let sliced_packet = SlicedPacket::from_ethernet(&raw_packet);
        match sliced_packet {
            Err(e) => log::warn!("Err {:?} --- discarding packet", e),
            Ok(packet) => {
                let packet_clone = packet.clone();
                if let Some(identifier) = StreamIdentifier::from_sliced_packet(&packet) {
                    let new_packets = match self.stream_data.get_mut(&identifier) {
                        Some(stream) => stream.process(packet_clone),
                        None => {
                            let mut stream = Stream::new(identifier, self.sender.clone());
                            stream.process(packet_clone);
                            self.stream_data.insert(identifier, stream);
                        }
                    };
                }
            }
        }
    }
}
