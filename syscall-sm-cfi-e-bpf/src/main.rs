use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;

// Change this to the SRC dir of unistd.h file that coresponds the the machines architecture
const UNISTD_SRC_DIR: &str = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    syscalls::init(UNISTD_SRC_DIR);

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

    let program: &mut TracePoint = bpf.program_mut("tracepoint_program").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_pread64")?;
    program.attach("syscalls", "sys_enter_read")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");


    Ok(())
}
