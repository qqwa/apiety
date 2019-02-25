//! Read memeroy of an running process to find salsa20 keys

// TODO: error types etc.

use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::str::FromStr;

use sysinfo::{ProcessExt, SystemExt};

pub fn get_process_pid(process_name: &str) -> usize {
    let system = sysinfo::System::new();
    let pid = system.get_process_by_name(process_name)[0].pid() as usize;
    pid
}

/// Used to search the memory of process
///
/// # Example
/// ```no_run
///     use poeproto::mem::ProcessMemory;
///     let prog = ProcessMemory::new(1337);
///     let positions = prog.search(&b"expand 32-byte k"[..], 2*1024*2014);
///     for position in positions {
///         let mut buffer = vec![0u8; 64];
///         prog.get(position as u64, &mut buffer);
///         println!("{:02x?}", buffer);
///     }
/// ```
pub struct ProcessMemory {
    pid: usize,
    maps: Vec<Map>,
}

impl ProcessMemory {
    /// Creates a new ProcessMemory struct with the given PID
    pub fn new(pid: usize) -> ProcessMemory {
        let path_maps = format!("/proc/{}/maps", pid);
        let mut file_maps = File::open(path_maps).expect("couldn't open maps file");
        let mut data = String::new();
        file_maps.read_to_string(&mut data).unwrap();

        let mut maps: Vec<Map> = Vec::with_capacity(data.lines().count());
        for line in data.lines() {
            let map = Map::parse(&line);
            maps.push(map);
        }
        ProcessMemory { pid, maps }
    }

    /// Search the memory of the process for all occurrences of the magic pattern
    /// returns a vector with addresses of the first byte
    pub fn search(&self, magic: &[u8], min_size: u64) -> Vec<usize> {
        let path = format!("/proc/{}/mem", self.pid);
        let mut file = File::open(path).expect("coundn't open mem file");
        let mut result: Vec<usize> = Vec::new();

        let mut buffer = vec![0u8; 0];

        for map in self.maps.iter() {
            let size = map.end - map.start;
            if map.private && map.permission | 6 >= 6 && min_size < size {
                let bytes = map.end - map.start;
                file.seek(SeekFrom::Start(map.start)).expect("seek failed");

                buffer.resize(bytes as usize, 0);
                if let Err(x) = file.read_exact(&mut buffer) {
                    println!("{:?}", x);
                    continue;
                }

                for i in 0..(bytes / 4) as usize {
                    if buffer.len() < (i * 4) + magic.len() {
                        break;
                    }
                    if &buffer[i * 4..(i * 4) + magic.len()] == magic {
                        result.push(map.start as usize + i * 4);
                    }
                }
            }
        }

        result
    }

    /// Copies memory from pos into the buffer
    pub fn get(&self, pos: u64, buffer: &mut [u8]) {
        let path = format!("/proc/{}/mem", self.pid);
        let mut file = File::open(path).expect("coundn't open mem file");

        file.seek(SeekFrom::Start(pos)).expect("seek failed");
        file.read_exact(buffer).unwrap();
    }
}

#[derive(Eq, PartialEq, Default, Debug)]
pub struct Map {
    start: u64,
    end: u64,
    permission: u8,
    private: bool,
    offset: u64,
    //    dev_id: u32,
    inode: u64,
    pathname: Option<String>,
}

impl Map {
    pub fn parse(string: &str) -> Map {
        let re = Regex::new(r"(?m)(?P<start>[a-f0-9]+)-(?P<end>[a-f0-9]+)\s(?P<perm>[rwxps-]{4})\s(?P<off>[a-f0-9]+)\s[a-f0-9]+:[a-f0-9]+\s(?P<inode>[0-9]+)\s*(?P<path>\S*)").unwrap();
        let caps = re.captures(&string).expect("caps");
        let start = u64::from_str_radix(&caps["start"], 16).expect("start");
        let end = u64::from_str_radix(&caps["end"], 16).expect("end");
        let mut permission = 0u8;
        for char in caps["perm"][..3].chars() {
            permission <<= 1;
            permission += match char {
                '-' => 0,
                _ => 1,
            };
        }
        let private = (&caps["perm"][3..]).chars().next().expect("private") == 'p';
        let offset = u64::from_str_radix(&caps["off"], 16).expect("offset");
        let inode = u64::from_str(&caps["inode"]).expect("inode");
        let pathname = match &caps["path"] {
            "" => None,
            x => Some(x.to_string()),
        };
        Map {
            start,
            end,
            permission,
            private,
            offset,
            inode,
            pathname,
            ..Map::default()
        }
    }
}

mod tests {
    use super::*;
    #[test]
    fn parse_maps_file() {
        let case = "55a23140c000-55a231f99000 r-xp 000000aa 08:02 3839391                    /usr/bin/qemu-system-x86_64";
        let vor = Map {
            start: 0x55a23140c000,
            end: 0x55a231f99000,
            permission: 5,
            private: true,
            offset: 0xaa,
            inode: 3839391,
            pathname: Some("/usr/bin/qemu-system-x86_64".to_string()),
        };

        assert_eq!(Map::parse(case), vor, "Parsed from: \"{}\"", case);
    }
}
