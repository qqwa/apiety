//! Caputre network traffic

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::packet::{Direction, PoePacket};
use crate::Error;

struct NetPacket {
    direction: crate::packet::Direction,
    ip: std::net::Ipv4Addr,
    port: u16,
    payload: Vec<u8>,
    push: bool,
}

impl NetPacket {
    pub fn new(
        payload_slice: &[u8],
        direction: Direction,
        ip: std::net::Ipv4Addr,
        port: u16,
        push: bool,
    ) -> Self {
        let mut payload = Vec::with_capacity(payload_slice.len());
        payload.extend_from_slice(&payload_slice[..]);

        NetPacket {
            direction,
            payload,
            ip,
            port,
            push,
        }
    }
}

fn net_packet_from_pnet(packet: &[u8]) -> Result<NetPacket, Error> {
    let payload_length;

    let ethernet = if let Some(eth) = EthernetPacket::owned(packet.to_vec()) {
        eth
    } else {
        return Err(Error::PNetError);
    };

    let (ip, tcp) = {
        let ipv4 = if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
            ipv4
        } else {
            return Err(Error::PNetError);
        };
        let tcp = if let Some(tcp) = MutableTcpPacket::owned(ipv4.payload().to_vec()) {
            let tl = ipv4.get_total_length() as usize;
            let ihl = ipv4.get_header_length() as usize;
            payload_length = tl - (ihl + tcp.get_data_offset() as usize) * 4;
            tcp
        } else {
            return Err(Error::PNetError);
        };
        let ip = if tcp.get_destination() == 6112 || tcp.get_destination() == 20481 {
            ipv4.get_destination()
        } else {
            ipv4.get_source()
        };
        (ip, tcp)
    };

    if payload_length == 0 {
        return Err(Error::PNetError);
    }

    let (direction, port) = if tcp.get_source() == 20481 {
        (Direction::FromLoginserver, tcp.get_destination())
    } else if tcp.get_destination() == 20481 {
        (Direction::ToLoginserver, tcp.get_source())
    } else if tcp.get_source() == 6112 {
        (Direction::FromGameserver, tcp.get_destination())
    } else if tcp.get_destination() == 6112 {
        (Direction::ToGameserver, tcp.get_source())
    } else {
        panic!("Tried to create PoePacket from unknown port");
    };

    let push = tcp.get_flags() & pnet::packet::tcp::TcpFlags::PSH != 0;

    Ok(NetPacket::new(
        &tcp.payload()[..payload_length],
        direction,
        ip,
        port,
        push,
    ))
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::Packet;

#[cfg(windows)]
use pnet::datalink::pcap::{interfaces, channel, Config};
#[cfg(not(windows))]
use pnet::datalink::{interfaces, channel, Config};

// listens on all interfaces and searches for packets to/from port 20481, if found shuts down all
// interfaces, but the one that found it
// the remaining interface sends all captured packets with ports 20481 and 6112
pub fn capture_from_interface(
    sender: mpsc::Sender<PoePacket>,
) -> Result<Vec<mpsc::Sender<()>>, crate::Error> {
    use pnet::datalink::Channel::Ethernet;

    let found_stream = Arc::new(AtomicBool::new(false));
    let mut kill_switches = Vec::new();

    for interface in interfaces() {
        let found_stream = found_stream.clone();
        let sender = sender.clone();

        let (kill_tx, kill_rx) = mpsc::channel();

        kill_switches.push(kill_tx);

        let mut rx = match channel(
            &interface,
            Config {
                read_timeout: Some(Duration::from_secs(1)),
                ..Default::default()
            },
        ) {
            Ok(Ethernet(_, rx)) => rx,
            Ok(_) => panic!("packetdump: unhandled channel type: {}"),
            Err(_) => return Err(crate::Error::NoPermission),
        };

        let _ = thread::Builder::new()
            .name(interface.name.to_string())
            .spawn(move || {
                // Create a channel to receive on

                let mut found = false;
                let mut bufferd_packets: HashMap<u16, RefCell<Vec<NetPacket>>> = HashMap::new();
                loop {
                    if found_stream.load(Ordering::SeqCst) && !found {
                        // other interface found packet, so we can shut this one down
                        break;
                    }
                    let kill_message = kill_rx.try_recv();
                    match kill_message {
                        Ok(()) => {
                            break;
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                        // communication channel broke, shutdown thread
                        Err(mpsc::TryRecvError::Disconnected) => {
                            break;
                        }
                    }
                    match rx.next() {
                        Ok(packet) => {
                            if filter(&packet, &interface.name) {
                                let swap =
                                    found_stream.compare_and_swap(false, true, Ordering::Relaxed);
                                if found_stream.load(Ordering::SeqCst) && !swap {
                                    found = true;
                                }

                                if found {
                                    let capture_packet =
                                        if let Ok(x) = net_packet_from_pnet(&packet) {
                                            x
                                        } else {
                                            continue;
                                        };
                                    if capture_packet.push {
                                        if let Some(bufferd_packets) =
                                            bufferd_packets.remove(&capture_packet.port)
                                        {
                                            let buffer = bufferd_packets.borrow_mut();
                                            let mut payload = Vec::new();
                                            for packet in buffer.iter() {
                                                payload.extend_from_slice(&packet.payload[..]);
                                            }
                                            payload.extend_from_slice(&capture_packet.payload[..]);
                                            let poepacket = PoePacket::new(
                                                &payload[..],
                                                capture_packet.direction,
                                                capture_packet.ip,
                                                capture_packet.port,
                                            );
                                            sender.send(poepacket).unwrap();
                                        } else {
                                            let poepacket = PoePacket::new(
                                                &capture_packet.payload[..],
                                                capture_packet.direction,
                                                capture_packet.ip,
                                                capture_packet.port,
                                            );
                                            sender.send(poepacket).unwrap();
                                        }
                                    } else {
                                        if bufferd_packets.contains_key(&capture_packet.port) {
                                            let mut buffer = bufferd_packets
                                                .get_mut(&capture_packet.port)
                                                .unwrap()
                                                .borrow_mut();
                                            buffer.push(capture_packet);
                                        } else {
                                            bufferd_packets.insert(
                                                capture_packet.port,
                                                RefCell::new(vec![capture_packet]),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            use std::io::ErrorKind;
                            if e.kind() != ErrorKind::TimedOut {
                                //                            panic!("{}: unable to receive packet: {:?}", interface.name, e);
                                //interface is probably down, just leave loop and let the thread exit
                                break;
                            }
                        }
                    }
                }
                //            println!("{} exited {:?} {:?}", &interface.name, found, found_stream);
            });
    }

    Ok(kill_switches)
}

fn filter(packet: &[u8], name: &str) -> bool {
    let ether = if let Some(x) = EthernetPacket::new(packet) {
        x
    } else {
        return false;
    };
    match ether.get_ethertype() {
        EtherTypes::Ipv4 => {
            let header = Ipv4Packet::new(ether.payload());
            if let Some(header) = header {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(header.payload());
                        if let Some(tcp) = tcp {
                            if tcp.get_source() == 20481
                                || tcp.get_destination() == 20481
                                || tcp.get_source() == 6112
                                || tcp.get_destination() == 6112
                            {
                                return true;
                            }
                        }
                    }
                    _ => return false,
                }
            } else {
                println!("[{}]: Malformed IPv4 Packet", name);
            }
        }
        _ => return false,
    }
    return false;
}
