//! Serialise and deserialise common types in packets

use std::fmt;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    ToGameserver,
    FromGameserver,
    ToLoginserver,
    FromLoginserver,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Direction::ToGameserver => "C  -> GS",
                Direction::FromGameserver => "C <-  GS",
                Direction::ToLoginserver => "C  -> LS",
                Direction::FromLoginserver => "C <-  LS",
            }
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PoePacket {
    pub direction: Direction,
    pub ip: std::net::Ipv4Addr,
    pub port: u16,
    pub payload: Vec<u8>,
}

impl fmt::Display for PoePacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}({}) id: {:02x?}, size: {}",
            self.direction,
            self.ip,
            &self.payload[..2],
            self.payload.len()
        )
    }
}

impl PoePacket {
    pub fn new(
        payload_slice: &[u8],
        direction: Direction,
        ip: std::net::Ipv4Addr,
        port: u16,
    ) -> Self {
        let mut payload = Vec::with_capacity(payload_slice.len());
        payload.extend_from_slice(&payload_slice[..]);

        PoePacket {
            direction,
            payload,
            ip,
            port,
        }
    }
}
