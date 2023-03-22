use std::{
    env,
    io::{Write, Read},
    path::PathBuf,
    fs::File,
};
use std::str::from_utf8;
use log::{info, error};

// Change this to where you'r unistd file is located.
const UNISTD_SRC_DIR: &str = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h";

const STD_PREFIX: &str = "#define __NR_";
const REL_FILE_DIR: &str = "syscalls/src/syscalls.rs";

fn main() -> Result<(), ()>{
    env_logger::init();

    // Variable to store the content of the rust src file
    let mut content = String::new();
    let mut content_syscall_to_id = String::new();
    let mut content_id_to_syscall = String::new();
    content += "use std::collections::HashMap;\n";
    content_syscall_to_id += "lazy_static!{\n\tpub static ref SYSCALL_TO_ID: HashMap<&'static str, u16> = HashMap::from([\n";
    content_id_to_syscall += "lazy_static!{\n\tpub static ref ID_TO_SYSCALL: HashMap<u16, &'static str>= HashMap::from([\n";

    // Extract the syscalls and their id's from the system
    let mut unistd_src_file = File::open(UNISTD_SRC_DIR).unwrap();
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
        let syscall_id = data_split.next().unwrap();
        info!("Adding syscall {:3} | {}", syscall_id, syscall_name);
        content_syscall_to_id += &format!("\t\t(\"{}\", {}),\n", syscall_name, syscall_id);
        content_id_to_syscall += &format!("\t\t({}, \"{}\"),\n", syscall_id, syscall_name);
    }
    content_syscall_to_id += "]);\n}";
    content_id_to_syscall += "]);\n}";
    content += &content_syscall_to_id;
    content += "\n\n";
    content += &content_id_to_syscall;

    // Create the rust source file and dump the content
    let working_dir: String;
    match env::current_dir() {
        Ok(path) => {
            working_dir = String::from(path.to_str().unwrap());
            info!("Current working directory: {}", working_dir);
        },
        Err(e) => {
            error!("Error getting working directory: {:?}", e);
            return Err(());
        },
    }
    let mut full_src_file_dir = PathBuf::new();
    full_src_file_dir.push(working_dir);
    full_src_file_dir.push(REL_FILE_DIR);

    info!("Full file dir: {}", full_src_file_dir.display());

    let mut src_file = File::create(full_src_file_dir).unwrap();
    src_file.write_all(content.as_bytes()).unwrap();

    Ok(())
}
