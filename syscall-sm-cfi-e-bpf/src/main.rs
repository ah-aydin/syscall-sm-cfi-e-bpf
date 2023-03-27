use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya::maps::HashMap;
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;
use syscall_sm_cfi_e_bpf_common::{
    str_to_1,
    str_to_16,
    str_to_20,
    build_transition,
};
use std::fs;
use std::io::Read;
use serde::{Serialize, Deserialize};
use serde_json::{Map, Value};

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
    let mut transitions: HashMap<_, [u8; 20], [u8; 1]> = HashMap::try_from(bpf.map_mut("SYS_SM_TRANSITIONS")?)?;

    let entries = fs::read_dir(syscalls::RES_DIR).unwrap();
    for entry in entries {
        match entry {
            Ok(entry) => {
                if entry.path().extension().unwrap() != "json" {
                    continue;
                }
                info!("{}", syscalls::DEBUG_STR);
                info!("Found syscall SM file {}", entry.file_name().into_string().unwrap());

                let mut file = fs::File::open(entry.path().clone()).unwrap();
                let mut contents = String::new();
                file.read_to_string(&mut contents).expect("Failed to read file");

                let map: Map<String, Value> = serde_json::from_str(&contents).expect("Failed to parse JSON");
                let bin_name = match map.get("binary").unwrap() {
                    Value::String(s) => s,
                    _ => panic!("Unsuppored binary name"),
                };
                tracked_binaries.insert(str_to_16(bin_name), str_to_1(" "), 0).unwrap();
                info!("Adding syscall SM for {}", bin_name);

                let sm = match map.get("data") {
                    Some(Value::Object(o)) => o,
                    _ => panic!("Failed to get data object"),
                };

                for (key, value) in sm.iter() {
                    match value {
                        Value::Array(a) => {
                            for v in a {
                                if let Value::String(s) = v {
                                    info!("Transition {} -> {}", key, s);
                                    let transition = build_transition(
                                        bin_name,
                                        syscalls::get_syscall_id(String::from(key)).unwrap(),
                                        syscalls::get_syscall_id(String::from(key)).unwrap()
                                        );
                                    transitions.insert(transition, str_to_1(" "), 0).unwrap();
                                }
                            }
                        },
                        _ => panic!("Invalid dependencies value"),
                    }
                }

                info!("{}", syscalls::DEBUG_STR);
            }
            Err(_) => {}
        };
    }


    let program: &mut TracePoint = bpf.program_mut("tracepoint_program").unwrap().try_into()?;
    program.load()?;
    // Attach the eBPF program to every syscall tracepoint
    for tp in syscalls::get_entry_tracepoints().iter() {
        program.attach("syscalls", tp)?;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");


    Ok(())
}
