#![no_std]
#![no_main]

use aya_bpf::{
    macros::{
        tracepoint,
        map,
    },
    programs::TracePointContext,
    cty::c_long,
    helpers::{
        bpf_get_current_comm,
        bpf_send_signal_thread
    },
    maps::HashMap,
};
use aya_log_ebpf::info;
use core::str::from_utf8_unchecked;
use syscall_sm_cfi_e_bpf_common::{
    str_to_1,
    str_to_256,
    str_to_270,
};

const SYSCALL_NR_OFFSET: usize = 8;
const SIGTERM: u32 = 15;

#[map(name = "SYS_SM_TRACKED_BINARIES")]
static mut SYS_SM_TRACKED_BINARIES: HashMap<[u8; 256], [u8; 1]> = HashMap::<[u8; 256], [u8; 1]>::with_max_entries(10, 0);

#[map(name = "SYS_SM_TRANSITIONS")]
static mut SYS_SM_TRANSITIONS: HashMap<[u8; 270], [u8; 1]> = HashMap::<[u8; 270], [u8; 1]>::with_max_entries(1024, 0);

#[map(name = "SYS_SM_LAST_SYSCALL")]
static mut SYS_SM_LAST_SYSCALL: HashMap<[u8; 256], u16> = HashMap::<[u8; 256], u16>::with_max_entries(10, 0);

#[tracepoint(name = "tracepoint_program")]
pub fn tracepoint_program(ctx: TracePointContext) -> c_long {
    match try_tracepoint_program(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint_program(ctx: TracePointContext) -> Result<c_long, c_long> {
    let syscall_nr: u32 = unsafe { ctx.read_at(SYSCALL_NR_OFFSET)? };
    let bin_bytes = bpf_get_current_comm()?;
    let bin_name = unsafe { from_utf8_unchecked(&bin_bytes) };

    if unsafe { SYS_SM_TRACKED_BINARIES.get(&str_to_256(bin_name)).is_none() } {
        return Ok(0);
    }

    info!(&ctx, "TERMINATED: syscall is entered {} bin_name: {}", syscall_nr, bin_name);
    unsafe { bpf_send_signal_thread(SIGTERM) };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
