use std::os::raw::c_void;

use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;

#[no_mangle]
pub unsafe extern fn salsa20_new(key: *const u8, iv: *const u8) -> *mut c_void {
    let key: &[u8] = std::slice::from_raw_parts(key, 32);
    let iv: &[u8] = std::slice::from_raw_parts(iv, 8);
    Box::into_raw(Box::new(Salsa20::new(&key, &iv))) as *mut c_void
}

#[no_mangle]
pub extern fn salsa20_free(ptr: *mut c_void) {
    if ptr.is_null() { return }
    unsafe { Box::from_raw(ptr); }
}

#[no_mangle]
pub extern fn salsa20_process(ptr: *mut c_void, buffer: *mut u8, buffer_len: usize) {
    let salsa20: &mut Salsa20 = unsafe {
        assert!(!ptr.is_null());
        &mut *(ptr as *mut crypto::salsa20::Salsa20)
    };
    let buffer: &mut [u8] = unsafe {
        assert!(!buffer.is_null());
        std::slice::from_raw_parts_mut(buffer, buffer_len)
    };
    let mut output: Vec<u8> = vec![0u8; buffer.len()];
    salsa20.process(&buffer[..], &mut output[..]);
    buffer.clone_from_slice(&output);
}