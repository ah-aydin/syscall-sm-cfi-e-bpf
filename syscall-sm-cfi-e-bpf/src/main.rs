use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya::maps::{HashMap, Array};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;
use syscall_sm_cfi_e_bpf_common::{
    str_to_1,
    str_to_16,
    str_to_20,
};

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

    let mut tracked_binaries: HashMap<_, [u8; 16], [u8; 1]> = HashMap::try_from(bpf.map_mut("SYS_SM_TRACKED_BINARIES")?)?;
    //let mut transitions: HashMap<_, TransitionEntry, [u8; 1]> = HashMap::try_from(bpf.map_mut("SYS_SM_TRANSITIONS")?)?;
    tracked_binaries.insert(str_to_16("cat"), str_to_1(" "), 0).unwrap();
    tracked_binaries.insert(str_to_16("ls"), str_to_1(" "), 0).unwrap();
    // Populate syscall transitions
    // Attach the eBPF program to all the sys_enter_* tracepoints

    let program: &mut TracePoint = bpf.program_mut("tracepoint_program").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_access")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");


    Ok(())
}
