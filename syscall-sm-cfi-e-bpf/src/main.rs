use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    syscalls::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syscall-sm-cfi-e-bpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/syscall-sm-cfi-e-bpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // TODO load eBPF maps
    // Populate binary names
    // Populate syscall transitions
    // Attach the eBPF program to all the sys_enter_* tracepoints

    let program: &mut TracePoint = bpf.program_mut("tracepoint_program").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_brk")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");


    Ok(())
}
