#![no_std]

pub fn str_to_1(s: &str) -> [u8; 1] {
    let mut result = [0; 1];
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len > 1 {
        panic!("String is too long");
    }
    result[..len].copy_from_slice(bytes);
    result
}

pub fn str_to_256(s: &str) -> [u8; 256] {
    let mut result = [0; 256];
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len > 256 {
        panic!("String is too long");
    }
    result[..len].copy_from_slice(bytes);
    result
}

pub fn str_to_270(s: &str) -> [u8; 270] {
    let mut result = [0; 270];
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len > 270 {
        panic!("String is too long");
    }
    result[..len].copy_from_slice(bytes);
    result
}
