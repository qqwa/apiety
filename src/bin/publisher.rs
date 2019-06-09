//! Sends decrypted packets to pipe, so that other programs can use it
use std::io::Write;
use std::net::TcpListener;

use std::sync::{Arc, Mutex};

fn main() {
    let clients = Arc::new(Mutex::new(Vec::new()));
    let clients_listerner = clients.clone();

    std::thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:10001").expect("Failed to bind TcpListerner");
        for stream in listener.incoming() {
            let mut clients = clients_listerner.lock().expect("Failed to lock clients_listerner");
            clients.push(stream.expect("Failed to push new client to clients_listerner"));
        }
    });

    let (packets, control) = apiety::decrypted_stream();
    loop {
        match packets.recv() {
            Ok(packet) => {
                println!("{}", packet);
                let mut clients = clients.lock().expect("Failed to lock clients_listerner");
                let buf = packet.to_buf();
                let mut remove_list = Vec::new();
                for i in 0..clients.len() {
                    match clients[i].write(&buf) {
                        Err(_) => {
                            remove_list.push(i);
                            continue;
                        }
                        _ => {}
                    }
                }
                for i in remove_list.iter().rev() {
                    clients.remove(*i);
                }
            }
            Err(e) => {
                println!("error: {:?}", e);
                control.send(apiety::Control::Shutdown).expect("Failed to send shutdown message to control");
                break;
            }
        }
    }
}
