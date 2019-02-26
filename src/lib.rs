#![feature(proc_macro_hygiene, decl_macro)]
#![feature(box_patterns)]
#![allow(proc_macro_derive_resolution_fallback)]

mod crypt;
mod mem;
mod net;
mod packet;

use std::sync::mpsc::{self, channel, Receiver, Sender};
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

pub fn decrypted_stream() -> (Receiver<PoePacket>, Sender<Control>) {
    let (packet_tx, packet_rx) = channel();
    let (handle, control_tx, packet) = encrypted_stream().unwrap();
    let (con, control_rx) = channel();

    std::thread::Builder::new()
        .name("decrypted_stream thread".to_string())
        .spawn(move || {
            let mut session = crypt::Session::new();

            loop {
                match control_rx.try_recv() {
                    Ok(control) => match control {
                        Control::Shutdown => {
                            control_tx.send(Control::Shutdown).unwrap();
                            break;
                        }
                        _ => {}
                    },
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // communication channel broke, shutdown thread
                        log::warn!("Control channel decrypted_stream broke");
                        control_tx.send(Control::Shutdown).unwrap();
                        break;
                    }
                }

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

            control_tx.send(Control::Shutdown).unwrap();

            handle.join().unwrap();
        })
        .unwrap();

    (packet_rx, con)
}

// returns handles, sender to shutdown threads and receiver to get packets
fn encrypted_stream() -> Result<
    (
        std::thread::JoinHandle<()>,
        Sender<Control>,
        Receiver<packet::PoePacket>,
    ),
    Error,
> {
    let (control_tx, control_rx) = channel();
    let (packet_tx, packet_rx) = channel();

    let kill_switches = net::capture_from_interface(packet_tx)?;

    let handle = std::thread::Builder::new()
        .name("encrypted_stream thread".to_string())
        .spawn(move || {
            let mut running = true;
            while running {
                match control_rx.recv() {
                    Ok(control) => match control {
                        Control::Shutdown => {
                            log::info!("Shutting down network sniffer");
                            running = false;
                        }
                        _ => {}
                    },
                    Err(e) => {
                        log::warn!("Control channel broke: {}", e);
                    }
                }
            }

            for kill_switch in kill_switches {
                // we don't care about result, if one fails that means
                // the thread is already finished
                let _ = kill_switch.send(());
            }
        })
        .expect("failed to start control thread for network sniffer");

    Ok((handle, control_tx, packet_rx))
}
