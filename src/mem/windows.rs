pub struct ProcessMemory {
    pid: usize,
}

impl ProcessMemory {
    /// Creates a new ProcessMemory struct with the given PID
    pub fn new(pid: usize) -> ProcessMemory {
        ProcessMemory { pid }
    }

    /// Search the memory of the process for all occurrences of the magic pattern
    /// returns a vector with addresses of the first byte
    pub fn search(&self, magic: &[u8], size: usize, min_size: u64) -> Vec<Vec<u8>> {
        use winapi::shared::minwindef::{BOOL, LPCVOID, LPVOID};
        use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::psapi::{QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION};
        use winapi::um::winnt::{
            MEMORY_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PVOID,
        };

        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false as BOOL,
                self.pid as u32,
            )
        };

        let mut address = 0usize;
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::uninitialized() };

        let mut count = 0;

        let mut bytes_read = 0;
        let mut bytes_skip = 0;

        let mut result = Vec::new();

        loop {
            let res = unsafe {
                VirtualQueryEx(
                    handle,
                    address as LPCVOID,
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if res == 0 {
                // no bytes returned == no more memory to read
                break;
            }

            let mut page_info: PSAPI_WORKING_SET_EX_INFORMATION =
                unsafe { std::mem::uninitialized() };
            page_info.VirtualAddress = info.BaseAddress;
            // returns 0 if it fails
            let _ = unsafe {
                QueryWorkingSetEx(
                    handle,
                    &mut page_info as *mut PSAPI_WORKING_SET_EX_INFORMATION as PVOID,
                    std::mem::size_of::<PSAPI_WORKING_SET_EX_INFORMATION>() as u32,
                )
            };

            if page_info.VirtualAttributes.Valid() != 0 && min_size as usize <= info.RegionSize {
                let mut buffer: Vec<u8> = vec![0u8; info.RegionSize as usize];
                let mut bytes = 0;
                unsafe {
                    ReadProcessMemory(
                        handle,
                        address as LPCVOID,
                        buffer.as_mut_ptr() as LPVOID,
                        info.RegionSize as usize,
                        &mut bytes,
                    );
                }

                // search salsa20 key
                //                let magic = &b"expand 32-byte k"[..];
                for i in 0..bytes / 4 {
                    if buffer.len() < (i * 4) + magic.len() || buffer.len() < (i * 4) + size {
                        break;
                    }
                    if &buffer[i * 4..(i * 4) + magic.len()] == magic {
                        let mut buf: Vec<u8> = Vec::with_capacity(size);
                        buf.extend_from_slice(&buffer[i * 4..(i * 4) + size]);
                        result.push(buf);
                        // println!("Found key at base: {:x?}, with size: 0x{:x?}", info.BaseAddress, info.RegionSize);
                        // println!("Found key 0x{:x?} @ {:x?}", info.RegionSize, info.BaseAddress);
                    }
                }

                bytes_read += info.RegionSize as usize;
                count += 1;
            } else {
                bytes_skip += info.RegionSize as usize;
            }

            address += info.RegionSize as usize;
            // println!("NextAddress: {:x?}", address);
        }
        result
    }
}
