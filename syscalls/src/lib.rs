mod state;

use std::{
    fs::{
        File,
        read_dir
    },
    io::Read,
    str::from_utf8,
};
use log::info;
use state::State;

static mut GLOBAL_STATE: Option<State> = None;

const STD_PREFIX: &str = "#define __NR_";

pub fn init(unistd_file_path: &str) {

    unsafe { GLOBAL_STATE = Some(State::new()) };

    // Get data from unist file
    let mut unistd_src_file = File::open(unistd_file_path).unwrap();
    let mut unistd_src_buffer = Vec::new();
    unistd_src_file.read_to_end(&mut unistd_src_buffer).unwrap();

    let unistd_src_lines = from_utf8(&unistd_src_buffer).unwrap().split("\n");
    for line in unistd_src_lines {
        if !line.contains(STD_PREFIX) {
            continue;
        }
        let data = &line[STD_PREFIX.len()..];
        let mut data_split = data.split_whitespace();
        let syscall_name = data_split.next().unwrap();
        let syscall_id: u16 = data_split.next().unwrap().parse().unwrap();
        info!("Adding syscall {:3} | {}", syscall_id, syscall_name);

        unsafe { GLOBAL_STATE.as_mut().unwrap().add_syscall(String::from(syscall_name), syscall_id) };
    }
    
    // Get list of kernel tracepoints for the eBPF program
    let tracepoint_dirs = read_dir("/sys/kernel/debug/tracing/events/syscalls").unwrap();
    for dir in tracepoint_dirs {
        let entry = dir.unwrap();
        if entry.file_type().unwrap().is_dir() {
            info!("Found tracepoint: {}", entry.file_name().to_string_lossy());
            unsafe { GLOBAL_STATE.as_mut().unwrap().add_tracepoint(String::from(entry.file_name().to_string_lossy())) };
        }
    }
}

pub fn get_syscall_id(syscall_name: String) -> Option<u16> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_syscall_id(syscall_name) }
}

pub fn get_syscall_name(syscall_id: u16) -> Option<String> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_syscall_name(syscall_id) }
}

pub fn get_entry_tracepoints() -> &'static Vec<String> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_entry_tracepoint_ref() }
}

pub fn get_exit_tracepoints() -> &'static Vec<String> {
    unsafe { GLOBAL_STATE.as_ref().unwrap().get_exit_tracepoint_ref() }
}
