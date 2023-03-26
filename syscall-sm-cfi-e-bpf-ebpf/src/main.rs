#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
    cty::c_long,
    helpers::{bpf_get_current_comm, bpf_send_signal_thread}
};
use aya_log_ebpf::info;

use core::str::from_utf8_unchecked;

// TODO create maps for binary names, transitions, and last syscall

const SYSCALL_NR_OFFSET: usize = 8;
const SIGTERM: u32 = 15;

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
    if !bin_name.contains("cat") {
        return Ok(0);
    }
    unsafe { bpf_send_signal_thread(SIGTERM) };

    info!(&ctx, "syscall is entered {} bin_name: {}", syscall_nr, bin_name);

    // TODO
    // Check if binary is tracked
    // Check if syscall transition is allowed
    //      if not terminate process
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
