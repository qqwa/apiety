//! Decrypt network

use std::cell::RefCell;

use crate::caputre_packets::StreamIdentifier;
use crate::packet::{Direction, PoePacket};
use byteorder::{ByteOrder, NetworkEndian};
use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use std::collections::HashMap;

use crate::Error;
use std::process::exit;

#[derive(Eq, PartialEq)]
enum State {
    Login,
    DetectingStateChange,
}

struct Connection {
    id: u32,
    recv: usize,
    send: usize,
    state: State,
    cipher: Option<(Salsa20, Salsa20)>,
}

impl Connection {
    fn new() -> Self {
        Connection {
            id: 0,
            recv: 0,
            send: 0,
            state: State::Login,
            cipher: None,
        }
    }
}

pub struct Session {
    keystore: HashMap<u32, KeyPair>,
    connections: HashMap<StreamIdentifier, RefCell<Connection>>,
}

impl Session {
    pub fn new() -> Session {
        Session {
            keystore: HashMap::new(),
            connections: HashMap::new(),
        }
    }

    pub fn add_keypair(&mut self, buffer1: &[u8], buffer2: &[u8]) -> Result<(), crate::Error> {
        if buffer1.len() != 64 || buffer2.len() != 64 {
            return Err(crate::Error::KeyWrongSize);
        }

        let (key1, iv_sender) = gen_salsa_key(buffer1);
        let (key2, iv_receiver) = gen_salsa_key(buffer2);

        if key1 != key2 {
            return Err(crate::Error::KeyDiffer);
        }

        let keypair = KeyPair {
            key: key1,
            iv_sender,
            iv_receiver,
        };

        let mut exists = false;
        for kp in self.keystore.values() {
            if *kp == keypair {
                exists = true;
            }
        }

        if exists {
            return Err(Error::WrongKey);
        }

        self.keystore.insert(0, keypair);
        log::info!("Inserted new 0 keypair");

        Ok(())
    }

    pub fn process(&mut self, mut packet: &mut PoePacket) -> Result<(), Error> {
        match packet.identifier.into() {
            Direction::FromGameserver | Direction::ToGameserver => {
                self.handle_gamepacket(&mut packet)?;
            }
            Direction::FromLoginserver | Direction::ToLoginserver => {
                self.handle_loginpacket(&mut packet)?;
            }
        }
        Ok(())
    }

    fn handle_gamepacket(&mut self, packet: &mut PoePacket) -> Result<(), Error> {
        if !self.connections.contains_key(&packet.identifier) {
            self.connections
                .insert(packet.identifier, RefCell::new(Connection::new()));
        }

        let mut conn = self
            .connections
            .get(&packet.identifier)
            .unwrap()
            .borrow_mut();
        let mut remove_conn = false;

        match conn.state {
            State::Login => {
                if Direction::ToGameserver == packet.identifier.into() {
                    match conn.send {
                        0 => {
                            if packet.payload.len() < 6 {
                                log::warn!("For some random reason we just tried to \"create\" a new game server connection if a to small packet...");
                                return Err(Error::StateBroke);
                            }
                            let connection_id = NetworkEndian::read_u32(&packet.payload[2..6]);
                            conn.id = connection_id;
                            log::info!("Getting keys from connection id: {}", connection_id);
                            let keypair = self.keystore.get(&connection_id);
                            if let Some(keypair) = keypair {
                                let send = Salsa20::new(&keypair.key, &keypair.iv_sender);
                                let recv = Salsa20::new(&keypair.key, &keypair.iv_receiver);

                                conn.cipher = Some((send, recv));
                            } else {
                                return Err(Error::NoKey);
                            }
                            conn.send += 1;
                        }
                        _ => {
                            return Err(Error::StateBroke);
                        }
                    }
                } else {
                    match conn.recv {
                        0 => {
                            if let Some((_, ref mut recv)) = conn.cipher {
                                let mut output: Vec<u8> = packet.payload.clone();
                                recv.process(&packet.payload[2..], &mut output[2..]);
                                packet.payload = output;
                                conn.recv += 1;
                            } else {
                                log::warn!("Tried to decrypt packet without having a key");
                                return Err(Error::NoKey);
                            }
                            conn.state = State::DetectingStateChange;
                        }
                        _ => {
                            return Err(Error::StateBroke);
                        }
                    }
                }
            }
            State::DetectingStateChange => {
                if Direction::ToGameserver == packet.identifier.into() {
                    if let Some((ref mut send, _)) = conn.cipher {
                        let mut output: Vec<u8> = vec![0u8; packet.payload.len()];
                        send.process(&packet.payload[..], &mut output[..]);
                        packet.payload = output;
                        conn.send += 1;
                    } else {
                        log::warn!("Tried to decrypt packet without having a key");
                        return Err(Error::NoKey);
                    }
                } else {
                    if let Some((_, ref mut recv)) = conn.cipher {
                        let mut output: Vec<u8> = vec![0u8; packet.payload.len()];
                        recv.process(&packet.payload[..], &mut output);
                        packet.payload = output;
                        conn.recv += 1;
                    } else {
                        log::warn!("Tried to decrypt packet without having a key");
                        return Err(Error::NoKey);
                    }
                }

                match &packet.payload[..2] {
                    // check if packet has id 0x1a to extract keypair
                    &[0x00, 0x1a] => {
                        let connection_id = NetworkEndian::read_u32(&packet.payload[14..18]);

                        let mut key: [u8; 32] = Default::default();
                        let mut iv_receiver: [u8; 8] = Default::default();
                        let mut iv_sender: [u8; 8] = Default::default();
                        key.copy_from_slice(&packet.payload[48..48 + 32]);
                        iv_sender.copy_from_slice(&packet.payload[48 + 32..48 + 32 + 8]);
                        iv_receiver.copy_from_slice(&packet.payload[48 + 48..48 + 48 + 8]);

                        self.keystore.insert(
                            connection_id,
                            KeyPair {
                                key,
                                iv_receiver,
                                iv_sender,
                            },
                        );
                        log::info!("Added keypair for connection id: {}", connection_id);
                    }
                    // check if packet has id 0x19 to remove connection
                    &[0x00, 0x19] => {
                        remove_conn = true;
                    }
                    _ => {}
                }
            }
        }

        if remove_conn {
            self.keystore.remove(&conn.id);
            std::mem::drop(conn);
            self.connections.remove(&packet.identifier);
        }

        Ok(())
    }

    fn handle_loginpacket(&mut self, packet: &mut PoePacket) -> Result<(), Error> {
        if !self.connections.contains_key(&packet.identifier) {
            self.connections
                .insert(packet.identifier, RefCell::new(Connection::new()));
        }

        let mut conn = self
            .connections
            .get(&packet.identifier)
            .unwrap()
            .borrow_mut();
        let mut remove_conn = false;

        match conn.state {
            State::Login => {
                if Direction::ToLoginserver == packet.identifier.into() {
                    match conn.send {
                        // unencrypted to nothing
                        0 => {
                            // first packet should have id 0x0002
                            if &[0x00, 0x02] != &packet.payload[..2] {
                                log::warn!(
                                    "ex: {:?}, got: {:?}",
                                    &[0x00, 0x02],
                                    &packet.payload[..2]
                                );
                                return Err(Error::UnexpectedPacket);
                            }
                            conn.send += 1;
                        }
                        // first packet to decrypt, check if key works
                        1 => {
                            if conn.cipher.is_none() {
                                let keypair = self.keystore.get(&0);
                                if let Some(keypair) = keypair {
                                    let send = Salsa20::new(&keypair.key, &keypair.iv_sender);
                                    let recv = Salsa20::new(&keypair.key, &keypair.iv_receiver);

                                    conn.cipher = Some((send, recv));
                                } else {
                                    return Err(Error::NoKey);
                                }
                                self.keystore.remove(&0);
                            }
                            if let Some((ref mut send, _)) = conn.cipher {
                                let mut output: Vec<u8> = vec![0u8; packet.payload.len()];
                                send.process(&packet.payload[..], &mut output[..]);
                                packet.payload = output;
                            } else {
                                log::warn!("Tried to decrypt packet without having a key");
                                return Err(Error::NoKey);
                            }
                            if &[0x00, 0x03] != &packet.payload[..2]
                                && &[0x00, 0x06] != &packet.payload[..2]
                            {
                                log::warn!(
                                    "Expected 0x0003 or 0x0006 got {:?}",
                                    &packet.payload[..2]
                                );
                                return Err(Error::WrongKey);
                            }
                            conn.send += 1;
                        }
                        // should not happen..
                        _ => {
                            return Err(Error::StateBroke);
                        }
                    }
                } else {
                    match conn.recv {
                        // unencrypted to nothing
                        0 => {
                            // first packet should have id 0x0002
                            if &[0x00, 0x02] != &packet.payload[..2] {
                                log::warn!(
                                    "ex: {:?}, got: {:?}",
                                    &[0x02, 0x04],
                                    &packet.payload[..2]
                                );
                                return Err(Error::UnexpectedPacket);
                            }
                            conn.recv += 1;
                        }
                        1 => {
                            if let Some((_, ref mut recv)) = conn.cipher {
                                let mut output: Vec<u8> = vec![0u8; packet.payload.len()];
                                recv.process(&packet.payload[..], &mut output);
                                packet.payload = output;
                                conn.recv += 1;
                            } else {
                                log::warn!("Tried to decrypt packet without having a key");
                                return Err(Error::NoKey);
                            }
                            if &[0x00, 0x04] != &packet.payload[..2] {
                                return Err(Error::WrongKey);
                            }
                            conn.state = State::DetectingStateChange;
                        }
                        // should not happen..
                        _ => {
                            return Err(Error::StateBroke);
                        }
                    }
                }
            }
            State::DetectingStateChange => {
                if Direction::ToLoginserver == packet.identifier.into() {
                    if let Some((ref mut send, _)) = conn.cipher {
                        let mut output: Vec<u8> = vec![0u8; packet.payload.len()];
                        send.process(&packet.payload[..], &mut output[..]);
                        packet.payload = output;
                        conn.send += 1;
                    } else {
                        log::warn!("Tried to decrypt packet without having a key");
                        return Err(Error::NoKey);
                    }
                } else {
                    if let Some((_, ref mut recv)) = conn.cipher {
                        let mut output: Vec<u8> = vec![0u8; packet.payload.len()];
                        recv.process(&packet.payload[..], &mut output);
                        packet.payload = output;
                        conn.recv += 1;
                    } else {
                        log::warn!("Tried to decrypt packet without having a key");
                        return Err(Error::NoKey);
                    }
                }

                match &packet.payload[..2] {
                    // check if packet has id 0x10 to extract keypair
                    &[0x00, 0x10] => {
                        let connection_id = NetworkEndian::read_u32(&packet.payload[10..14]);

                        let mut key: [u8; 32] = Default::default();
                        let mut iv_sender: [u8; 8] = Default::default();
                        let mut iv_receiver: [u8; 8] = Default::default();
                        key.copy_from_slice(&packet.payload[43..43 + 32]);
                        iv_sender.copy_from_slice(&packet.payload[43 + 32..43 + 32 + 8]);
                        iv_receiver.copy_from_slice(&packet.payload[43 + 48..43 + 48 + 8]);

                        self.keystore.insert(
                            connection_id,
                            KeyPair {
                                key,
                                iv_sender,
                                iv_receiver,
                            },
                        );
                        log::info!("Added keypair for connection id: {}", connection_id);
                    }
                    // check if packet has id 0x11 to remove connection
                    &[0x00, 0x11] => {
                        remove_conn = true;
                    }
                    _ => {}
                }
            }
        }

        if remove_conn {
            self.keystore.remove(&conn.id);
            std::mem::drop(conn);
            self.connections.remove(&packet.identifier);
        }

        Ok(())
    }
}

pub(crate) fn gen_salsa_key(buffer: &[u8]) -> ([u8; 32], [u8; 8]) {
    assert!(buffer.len() == 64);

    let tmp = buffer[16..16 + 48].to_vec();
    //    let mut chunks = tmp.chunks_mut(4);
    let mut tkey = Vec::with_capacity(32);
    let mut tiv = Vec::with_capacity(8);

    tkey.extend_from_slice(&tmp[9 * 4..10 * 4]);
    tkey.extend_from_slice(&tmp[6 * 4..7 * 4]);
    tkey.extend_from_slice(&tmp[3 * 4..4 * 4]);
    tkey.extend_from_slice(&tmp[0 * 4..1 * 4]);
    tkey.extend_from_slice(&tmp[11 * 4..12 * 4]);
    tkey.extend_from_slice(&tmp[8 * 4..9 * 4]);
    tkey.extend_from_slice(&tmp[5 * 4..6 * 4]);
    tkey.extend_from_slice(&tmp[2 * 4..3 * 4]);

    tiv.extend_from_slice(&tmp[10 * 4..11 * 4]);
    tiv.extend_from_slice(&tmp[7 * 4..8 * 4]);

    let mut key = [0u8; 32];
    let mut iv = [0u8; 8];
    key.clone_from_slice(&tkey[..]);
    iv.clone_from_slice(&tiv[..]);

    (key, iv)
}

#[derive(PartialEq, Eq)]
pub(crate) struct KeyPair {
    pub key: [u8; 32],
    pub iv_sender: [u8; 8],
    pub iv_receiver: [u8; 8],
}
