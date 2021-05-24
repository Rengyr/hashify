extern crate crc32fast;

use clap::{App, Arg};
use crc32fast::Hasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{metadata, File, Metadata};
use std::io::{BufRead, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::{fs, io, process};
use same_file::is_same_file;
use std::ffi::OsStr;

fn main() {
    let matches = App::new("Hashify")
        .version("1.2.1")
        .author("Rengyr <of@rengyr.eu>")
        .about("CRC32 hash.")
        .arg(
            Arg::with_name("recursive")
                .short("r")
                .long("recursive")
                .takes_value(false)
                .help("Enable recursive search"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true)
                .help("Output of hash file; Ignored if is in the scope"),
        )
        .arg(
            Arg::with_name("buffer")
                .short("b")
                .long("buffer")
                .takes_value(true)
                .help("Size of read buffer in KB"),
        )
        .arg(
            Arg::with_name("input")
                .takes_value(true)
                .help("Input file or directory"),
        )
        .get_matches();

    let input: &str = matches.value_of("input").unwrap_or("");

    let recursive: bool = matches.is_present("recursive");

    let output: &str = matches.value_of("output").unwrap_or("");

    let buffer_size: usize = matches
        .value_of("buffer")
        .unwrap_or("128")
        .parse::<usize>()
        .unwrap_or(128);

    if input.is_empty() {
        let mut hasher = Hasher::new();

        let temp_buffer: Vec<u8> = vec![0; 1024 * buffer_size];
        let mut buffer = temp_buffer.into_boxed_slice();
        let mut length = 1;

        while length > 0 {
            length = match io::stdin().read(&mut *buffer) {
                Ok(len) => len,
                Err(e) => {
                    eprintln!("Error when reading from stdin: {}", e);
                    process::exit(1);
                }
            };
            hasher.update(&buffer[..length]);
        }
        println!("{:08x}", hasher.finalize());
    } else {
        let metadata: Metadata = match metadata(input) {
            Ok(metadata) => metadata,
            Err(_) => {
                eprintln!("Input doesn't exit or insufficient permissions!");
                process::exit(1);
            }
        };

        if metadata.is_file() {
            match crc32_hash(PathBuf::from(input), buffer_size) {
                Ok(hash) => {
                    println!("{:08x}\t{}", hash, input);
                }
                Err(e) => {
                    if e.kind() != ErrorKind::PermissionDenied {
                        eprintln!("Error when calculating hash: {}", e);
                    }
                }
            }
        } else if metadata.is_dir() {
            let mut hashes: HashMap<String, u32> = HashMap::new();
            let mut hashes_old: HashMap<String, u32> = HashMap::new();
            let mut seen: HashSet<PathBuf> = HashSet::new();
            let mut directories: VecDeque<PathBuf> = VecDeque::new();
            directories.push_back(PathBuf::from(input));

            if Path::new(output).exists() {
                load_file(&mut hashes_old, output);
            }

            let output_path = Path::new(output);
            let output_file_name = output_path.file_name().unwrap_or(OsStr::new(""));

            loop {
                if directories.is_empty() {
                    break;
                } else {
                    let dir = directories.pop_front().unwrap();
                    for entry in match fs::read_dir(dir) {
                        Ok(entry) => entry,
                        Err(e) => {
                            if e.kind() != ErrorKind::PermissionDenied {
                                eprintln!("Error when iterating file: {}", e);
                            }
                            continue;
                        }
                    } {
                        let file = match entry {
                            Ok(entry) => entry,
                            Err(e) => {
                                if e.kind() != ErrorKind::PermissionDenied {
                                    eprintln!("Error when iterating file: {}", e);
                                }
                                continue;
                            }
                        };
                        let file_name = file.path();
                        if file.file_type().unwrap().is_file() {
                            let file_os_name= file.path().as_os_str().to_string_lossy().into_owned();
                            if file_name.file_name().unwrap() == output_file_name && is_same_file(&file_name, output_path).unwrap_or(false){
                                continue;
                            }
                            let hash = match crc32_hash(file_name, buffer_size) {
                                Ok(hash) => hash,
                                Err(e) => {
                                    if e.kind() != ErrorKind::PermissionDenied {
                                        eprintln!("Error when calculating hash: {}", e);
                                    }
                                    continue;
                                }
                            };
                            if hashes_old.contains_key(
                                &file_os_name,
                            ) {
                                let old_hash = hashes_old
                                    .get(&file_os_name)
                                    .unwrap();
                                if *old_hash != hash {
                                    eprintln!("File hash mismatch:\n\tFile: {}\n\tOld Hash: {:08x}\n\tNew Hash: {:08x}", file_os_name, old_hash, hash);
                                }
                            }
                            hashes.insert(
                                file_os_name,
                                hash,
                            );
                        } else if recursive && file.file_type().unwrap().is_dir() {
                            if !seen.contains(&file_name) {
                                seen.insert(file_name.clone());
                                directories.push_back(file_name);
                            }
                        }
                    }
                }
            }
            if output == "" {
                for (file, hash) in hashes.iter() {
                    println!("{:08x}\t{}", hash, file);
                }
            } else {
                let mut f = match File::create(output) {
                    Ok(file) => file,
                    Err(e) => {
                        eprintln!("Error when calculating hash: {}", e);
                        process::exit(1);
                    }
                };
                let mut iter:Vec<(&String, &u32)> = hashes.iter().collect();
                iter.sort_by(|(file_a,_),(file_b, _)|file_a.cmp(file_b));
                for (file, hash) in iter{
                    match f.write_all(format!("{:08x}\t{}\n", hash, file).as_bytes()) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Error when saving hashes: {}", e);
                            process::exit(1);
                        }
                    };
                }
            }
        }
    }
}

fn crc32_hash(input: PathBuf, buffer_size: usize) -> Result<u32, io::Error> {
    let mut hasher = Hasher::new();

    let mut f = File::open(input)?;
    let temp_buffer: Vec<u8> = vec![0; 1024 * buffer_size];
    let mut buffer = temp_buffer.into_boxed_slice();
    let mut length = 1;

    while length > 0 {
        length = f.read(&mut buffer)?;
        hasher.update(&buffer[..length]);
    }
    Ok(hasher.finalize())
}

fn load_file(hashes: &mut HashMap<String, u32>, file: &str) {
    let f = match File::open(file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error when loading hashes: {}", e);
            process::exit(1);
        }
    };

    for line in io::BufReader::new(f).lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("Error when loading hashes: {}", e);
                process::exit(1);
            }
        };
        if line.is_empty() {
            continue;
        }
        let splitted: Vec<&str> = line.splitn(2, '\t').collect();
        hashes.insert(
            splitted[1].to_owned(),
            u32::from_str_radix(splitted[0], 16).unwrap(),
        );
    }
}
