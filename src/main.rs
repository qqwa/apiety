//! Sends decrypted packets to pipe, so that other programs can use it
use std::io::Write;
use std::net::TcpListener;

use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(long, raw(requires_all = "&[\"key_s\", \"key_r\"]"))]
    pcap_file: Option<PathBuf>,
    #[structopt(long)]
    key_s: Option<String>,
    #[structopt(long)]
    key_r: Option<String>,
}

fn main() {
    env_logger::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Opt::from_args();
    println!("{:?}", opt);
    println!("Hello World!");

    // start thread to listen on port 10001 for other programs that are interested in decrypted packets
    let clients = Arc::new(Mutex::new(Vec::new()));
    let clients_listerner = clients.clone();

    std::thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:10001").expect("Failed to bind TcpListerner");
        for stream in listener.incoming() {
            let mut clients = clients_listerner
                .lock()
                .expect("Failed to lock clients_listerner");
            clients.push(stream.expect("Failed to push new client to clients_listerner"));
        }
    });

    // start packet capturing of raw/encrypted packets
    let (tx, packets) = channel();
    match opt.pcap_file {
        Some(pcap_file) => {
            apiety::caputre_packets::capture_from_file(tx, &pcap_file)
                .expect("couldn't capture from file");
        }
        None => {
            apiety::caputre_packets::capture_from_interface(tx)
                .expect("couldn't capture from interface");
        }
    }

    //    let mut decrypter = apiety::decrypter::Decrypter::new();
    let mut decrypter = apiety::crypt::Session::new();
    if let (Some(key_s), Some(key_r)) = (&opt.key_s, &opt.key_r) {
        let buffer1 = hex::decode(key_s).expect("Failed to decode key_s");
        let buffer2 = hex::decode(key_r).expect("Failed to decode key_r");
        if let Err(e) = decrypter.add_keypair(&buffer1, &buffer2) {
            log::warn!("{:?}", e);
        }
    }
    let (tx, rx) = channel();
    let mut stream_reassembly = apiety::caputre_packets::StreamReassembly::new(tx);
    let mut count = 0;
    //
    //    let (packets, control) = apiety::decrypted_stream();
    loop {
        if opt.key_s.is_none() && count == 2 {
            let pid = apiety::mem::get_process_pid("PathOfExile_x64.exe");
            let prog = apiety::mem::ProcessMemory::new(pid);
            let tmp_keys = prog.search(&b"expand 32-byte k"[..], 64, 1024);
            decrypter.add_keypair(&tmp_keys[0], &tmp_keys[1]);
        }
        match packets.recv() {
            Ok(packet) => {
                // process packet into NetPacket, returns everytime it got a fully assembled packet in the right order
                stream_reassembly.process(&packet);
                loop {
                    match rx.try_recv() {
                        Ok(mut packet) => {
                            //                            log::info!("RAW: {}", packet);
                            count += 1;
                            match decrypter.process(&mut packet) {
                                Ok(()) => log::info!("{}", packet),
                                Err(e) => log::warn!("Err: {:?}", e),
                            }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(e) => {
                            log::error!("Err: {}", e);
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                println!("error: {:?}", e);
                break;
            }
        }
    }
}
