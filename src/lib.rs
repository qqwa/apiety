pub mod caputre_packets;
mod crypt;
pub mod decrypter;
pub mod mem;
mod packet;

use std::sync::mpsc::{channel, Receiver};
use std::time::Instant;

pub use packet::Direction;
pub use packet::PoePacket;

#[derive(Debug)]
pub enum Error {
    NoKey,
    KeyWrongSize,
    KeyDiffer,
    WrongKey,
    NoPermission,
    PNetError,
    UnexpectedPacket,
    StateBroke,
    CanNotDeserialize,
}

pub enum Control {
    Shutdown,
    KeyPair([u8; 32], [u8; 8], [u8; 8]),
}

pub fn decrypted_stream() -> Receiver<PoePacket> {
    let (packet_tx, packet_rx) = channel();
    let packet = encrypted_stream().unwrap();

    std::thread::Builder::new()
        .name("decrypted_stream thread".to_string())
        .spawn(move || {
            let mut session = crypt::Session::new();

            loop {
                let mut packet_message = packet.recv();
                match packet_message {
                    Ok(ref mut packet) => {
                        let mut tries = 0;
                        'inner: loop {
                            let result = session.handle(packet);
                            match result {
                                Ok(()) => {
                                    packet_tx.send(packet.clone()).unwrap();
                                    break;
                                }
                                Err(Error::NoKey) | Err(Error::WrongKey) => {
                                    let start = Instant::now();

                                    // search memory for key
                                    let pid = mem::get_process_pid("PathOfExile_x64.exe");
                                    let prog = mem::ProcessMemory::new(pid);
                                    let tmp_keys = prog.search(&b"expand 32-byte k"[..], 64, 1024);
                                    let mut keys = Vec::new();
                                    for key in tmp_keys {
                                        let mut buffer = [0u8; 64];
                                        buffer.copy_from_slice(&key[..64]);
                                        keys.push(buffer);
                                    }

                                    let duration = start.elapsed();
                                    log::info!("Time elapsed while searching keys: {:?}", duration);

                                    for i in 0..keys.len() / 2 {
                                        if tries <= i {
                                            let key1 = &keys.get(i * 2);
                                            let key2 = &keys.get(i * 2 + 1);

                                            match (key1, key2) {
                                                (Some(key1), Some(key2)) => {
                                                    match session.add_key(&key1[..], &key2[..]) {
                                                        Ok(()) => {
                                                            tries += 1;
                                                            continue 'inner;
                                                        }
                                                        Err(_) => {}
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                    panic!("could not find key");
                                }
                                Err(e) => {
                                    panic!("Error: {:?}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Error: {}", e);
                        break;
                    }
                }
            }
        })
        .unwrap();

    packet_rx
}

// returns handles, sender to shutdown threads and receiver to get packets
pub fn encrypted_stream() -> Result<Receiver<packet::PoePacket>, Error> {
    let (capture_tx, capture_rx) = channel();
    let (packet_tx, packet_rx) = channel();

    // TODO: Arc::new(AtomicBool::new(false)); to stop capture threads
    caputre_packets::capture_from_interface(capture_tx)?;

    Ok(packet_rx)
}
