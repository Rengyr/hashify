extern crate byte_unit;
extern crate crc32fast;

use byte_unit::Byte;
use clap::{App, Arg};
use crc32fast::Hasher;
use rustc_hash::{FxHashMap, FxHashSet};
use same_file::is_same_file;
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::{metadata, File, Metadata};
use std::io::{BufRead, Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, io, process};

#[derive(PartialEq)]
enum Recursive {
    Yes,
    No,
}

#[derive(PartialEq)]
enum Quiet {
    Yes,
    No,
}

#[derive(PartialEq, PartialOrd)]
enum Verbose {
    Nothing,
    NewOldFiles,
    All,
}

struct Setting {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    buffer_size: usize,
    recursive: Recursive,
    quiet: Quiet,
    verbose: Verbose,
}

fn main() {
    let matches = App::new("Hashify")
        .version("1.3.3")
        .author("Dominik 'Rengyr' Kosík <of@rengyr.eu>")
        .about("CRC32 hash.")
        .arg(
            Arg::with_name("recursive")
                .short("r")
                .long("recursive")
                .takes_value(false)
                .help("Enable recursive search"),
        ).arg(
        Arg::with_name("quiet")
            .short("q")
            .conflicts_with("verbose")
            .long("quiet")
            .takes_value(false)
            .help("Disable statistics at the end"),
    )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true)
                .help("Output of hash file\nIts hash is ignored\nOutput is ignored for single file hash"),
        )
        .arg(
            Arg::with_name("buffer")
                .short("b")
                .long("buffer")
                .takes_value(true)
                .help("Size of read buffer in KB"),
        ).arg(
        Arg::with_name("verbose")
            .short("v")
            .conflicts_with("quiet")
            .multiple(true)
            .help("Sets the level of verbosity: (repeat for increased verbosity)\n\tLevel 1: Verbose info about new/removed files\n\tLevel 2: Verbose info about every file
                    "),
    )
        .arg(
            Arg::with_name("input")
                .takes_value(true)
                .help("Input file or directory"),
        )
        .get_matches();

    //Parsing arguments
    let input: &str = matches.value_of("input").unwrap_or("");

    let recursive: Recursive = match matches.is_present("recursive") {
        true => Recursive::Yes,
        false => Recursive::No,
    };

    let quiet: Quiet = match matches.is_present("quiet") {
        true => Quiet::Yes,
        false => Quiet::No,
    };

    let output: &str = matches.value_of("output").unwrap_or("");

    let verbose: Verbose = match matches.occurrences_of("verbose") {
        0 => Verbose::Nothing,
        1 => Verbose::NewOldFiles,
        2 => Verbose::All,
        _ => Verbose::All,
    };

    let buffer_size: usize = matches
        .value_of("buffer")
        .unwrap_or("128")
        .parse::<usize>()
        .unwrap_or(128);

    let settings = Setting {
        input: if input.is_empty() {
            None
        } else {
            Some(PathBuf::from(input))
        },
        output: if output.is_empty() {
            None
        } else {
            Some(PathBuf::from(output))
        },
        buffer_size,
        recursive,
        quiet,
        verbose,
    };

    //Read from stdin
    if settings.input.is_none() {
        let hash = match hash_from_input(io::stdin(), &settings) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        };
        println!("{:08x}", hash);
    } else {
        //Read file or directory
        let metadata: Metadata = match metadata(settings.input.as_deref().unwrap()) {
            Ok(metadata) => metadata,
            Err(_) => {
                eprintln!("Input doesn't exit or insufficient permissions!");
                process::exit(1);
            }
        };

        //Input is a file
        if metadata.is_file() {
            match crc32_hash(settings.input.as_deref().unwrap(), settings.buffer_size) {
                Ok(hash) => {
                    println!("{:08x}\t{}", hash.0, input);
                }
                Err(e) => {
                    if e.kind() != ErrorKind::PermissionDenied {
                        eprintln!("Error when calculating hash: {}", e);
                    }
                }
            }
        } else if metadata.is_dir() {
            //Input is a directory
            hashes_from_dir(&settings, &mut io::stdout(), &mut io::stderr());
        }
    }
}

//Calculate crc32 for given file
//Returns tuple (settings)
#[inline]
fn crc32_hash(file: &Path, buffer_size: usize) -> Result<(u32, u64), io::Error> {
    let mut hasher = Hasher::new();

    let mut read_bytes: u64 = 0;

    let mut f = File::open(file)?;
    let temp_buffer: Vec<u8> = vec![0; 1024 * buffer_size];
    let mut buffer = temp_buffer.into_boxed_slice();
    let mut length = 1;

    while length > 0 {
        length = f.read(&mut buffer)?;
        read_bytes += length as u64;
        hasher.update(&buffer[..length]);
    }
    Ok((hasher.finalize(), read_bytes))
}

//Calculate crc32 from readable input
fn hash_from_input<R: Read>(mut input: R, settings: &Setting) -> Result<u32, Error> {
    let mut hasher = Hasher::new();

    let temp_buffer: Vec<u8> = vec![0; 1024 * settings.buffer_size];
    let mut buffer = temp_buffer.into_boxed_slice();
    let mut length = 1;

    while length > 0 {
        length = match input.read(&mut *buffer) {
            Ok(len) => len,
            Err(e) => {
                return Err(Error::new(
                    e.kind(),
                    format!("Error when reading from stdin: {}", e),
                ));
            }
        };
        hasher.update(&buffer[..length]);
    }

    Ok(hasher.finalize())
}

//Calculate crc32 given directory
//Returns without doing anything if input  or output doesn't exist
fn hashes_from_dir<WS: Write, WE: Write>(settings: &Setting, mut out_std: WS, mut out_err: WE) {
    if settings.input.is_none() {
        return;
    }

    //Input is a directory
    let mut hashes: FxHashMap<String, u32> = FxHashMap::default();
    let mut hashes_old: FxHashMap<String, u32> = FxHashMap::default();
    let mut seen: FxHashSet<PathBuf> = FxHashSet::default();
    let mut directories: VecDeque<PathBuf> = VecDeque::new();
    directories.push_back(settings.input.clone().unwrap());

    //Init stats
    let mut read_bytes: u64 = 0;
    let mut files_processed: u64 = 0;
    let mut files_added: u64 = 0;
    let mut files_removed: u64 = 0;
    let mut files_skipped: u64 = 0;
    let start_time = Instant::now();

    //Load hashes if exists
    if settings.output.is_some() && settings.output.as_deref().unwrap().exists() {
        match load_file(&mut hashes_old, settings.output.as_deref().unwrap()) {
            None => {}
            Some(e) => {
                eprintln!("Error when loading hashes: {}", e);
                process::exit(1);
            }
        };
    }

    let output_file_name = match settings.output.as_deref() {
        Some(path) => path.file_name().unwrap_or_else(|| OsStr::new("")),
        None => OsStr::new(""),
    };

    //Iterate through directory/ies
    loop {
        if directories.is_empty() {
            break;
        }

        let dir = directories.pop_front().unwrap();
        for entry in match fs::read_dir(dir) {
            Ok(entry) => entry,
            Err(e) => {
                if e.kind() != ErrorKind::PermissionDenied {
                    writeln!(out_err, "Error when iterating file: {}", e).unwrap();
                }
                files_skipped += 1;
                continue;
            }
        } {
            let file = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    if e.kind() != ErrorKind::PermissionDenied {
                        writeln!(out_err, "Error when iterating file: {}", e).unwrap();
                    }
                    files_skipped += 1;
                    continue;
                }
            };
            let file_name = file.path();
            if file.file_type().unwrap().is_file() {
                let file_os_name = file.path().as_os_str().to_string_lossy().into_owned();
                if file_name.file_name().unwrap() == output_file_name
                    && is_same_file(
                        &file_name,
                        settings.output.as_deref().unwrap_or_else(|| Path::new("")),
                    )
                    .unwrap_or(false)
                {
                    continue;
                }
                let (hash, read) = match crc32_hash(&file_name, settings.buffer_size) {
                    Ok((hash, read)) => (hash, read),
                    Err(e) => {
                        if e.kind() != ErrorKind::PermissionDenied {
                            writeln!(out_err, "Error when calculating hash: {}", e).unwrap();
                        }
                        files_skipped += 1;
                        continue;
                    }
                };

                if hashes_old.contains_key(&file_os_name) {
                    let old_hash = hashes_old.get(&file_os_name).unwrap();
                    if *old_hash != hash {
                        writeln!(out_err, "File hash mismatch:\n\tFile: {}\n\tOld Hash: {:08x}\n\tNew Hash: {:08x}", file_os_name, old_hash, hash).unwrap();
                    } else if settings.verbose >= Verbose::All {
                        writeln!(
                            out_std,
                            "Known file found:\n\tFile: {}\n\tHash: {:08x}",
                            file_os_name, hash
                        )
                        .unwrap();
                    }
                } else {
                    files_added += 1;
                    if settings.verbose >= Verbose::NewOldFiles {
                        writeln!(
                            out_std,
                            "New file found:\n\tFile: {}\n\tHash: {:08x}",
                            file_os_name, hash
                        )
                        .unwrap();
                    }
                }

                read_bytes += read;
                files_processed += 1;
                hashes.insert(file_os_name, hash);
            } else if settings.recursive == Recursive::Yes
                && file.file_type().unwrap().is_dir()
                && !seen.contains(&file_name)
            {
                seen.insert(file_name.clone());
                directories.push_back(file_name);
            }
        }
    }
    //Print to stdout if output file not specified
    if settings.output.is_none() {
        for (file, hash) in &hashes {
            writeln!(out_std, "{:08x}\t{}", hash, file).unwrap();
        }
    } else {
        //Write to file if output file specified
        let removed_iter = hashes_old.iter().filter(|x| !hashes.contains_key(x.0));
        for (file, hash) in removed_iter {
            files_removed += 1;
            if settings.verbose >= Verbose::NewOldFiles {
                writeln!(
                    out_std,
                    "Removed file found:\n\tFile: {}\n\tHash: {:08x}",
                    file, hash
                )
                .unwrap();
            }
        }

        let mut f = match File::create(settings.output.as_deref().unwrap()) {
            Ok(file) => file,
            Err(e) => {
                writeln!(out_err, "Error when calculating hash: {}", e).unwrap();
                process::exit(1);
            }
        };
        let mut iter: Vec<(&String, &u32)> = hashes.iter().collect();
        iter.sort_by(|(file_a, _), (file_b, _)| file_a.cmp(file_b));
        for (file, hash) in iter {
            match f.write_all(format!("{:08x}\t{}\n", hash, file).as_bytes()) {
                Ok(_) => {}
                Err(e) => {
                    writeln!(out_err, "Error when saving hashes: {}", e).unwrap();
                    process::exit(1);
                }
            };
        }
    }
    //Print statistics
    if settings.quiet == Quiet::No {
        let elapsed = start_time.elapsed();
        let size = Byte::from_bytes(u128::from(read_bytes));

        println!("Statistics of the runtime:");
        println!(
            "\tElapsed time: {}:{}:{:.4}",
            elapsed.as_secs() / 3600,
            (elapsed.as_secs() / 60) % 60,
            (elapsed.as_secs_f32()) % 60.0
        );
        println!("\tFiles processed: {}", files_processed);
        println!("\tBytes processed: {}", size.get_appropriate_unit(true));
        println!("\tNumber of new files: {}", files_added);
        println!("\tNumber of removed files: {}", files_removed);
        println!("\tSkipped files due to permissions: {}", files_skipped);
    }
}

//Load hashes into HashMap
fn load_file(hashes: &mut FxHashMap<String, u32>, file: &Path) -> Option<io::Error> {
    let f = match File::open(file) {
        Ok(f) => f,
        Err(e) => {
            return Some(e);
        }
    };

    for line in io::BufReader::new(f).lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                return Some(e);
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
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_single_file() {
        //SETUP
        let dir = match TempDir::new("unit_tests") {
            Ok(dir) => dir,
            Err(e) => {
                panic!("Error when creating directory for unit test.\nError: {}", e);
            }
        };

        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Test string\nIn test file".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        //TEST
        let hash = match crc32_hash(&file_path, 32) {
            Ok(hash) => hash.0,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(0x38561ced, hash, "crc32 mismatch on test file.");

        //TEARDOWN
        match dir.close() {
            Ok(_) => {}
            Err(_) => {
                panic!("Error when deleting test file.")
            }
        };
    }

    #[test]
    fn test_input_stream() {
        //SETUP
        let input = "Test string\nIn test file";

        let settings = Setting {
            input: None,
            output: None,
            buffer_size: 32,
            recursive: Recursive::No,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //TEST
        let hash = match hash_from_input(input.as_bytes(), &settings) {
            Ok(hash) => hash,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(0x38561ced, hash, "crc32 mismatch on input stream.");
    }

    #[test]
    fn test_directory_stdout() {
        //SETUP
        let mut out_std: Vec<u8> = Vec::new();
        let mut out_err: Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests") {
            Ok(dir) => dir,
            Err(e) => {
                panic!("Error when creating directory for unit test.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Test string\nIn test file".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir.path().join("unit-test-file2");
        let mut f = match File::create(&file_path2) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Second file :3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: None,
            buffer_size: 32,
            recursive: Recursive::No,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //TEST
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        let out_raw = String::from_utf8_lossy(&out_std).into_owned();
        let out_parsed = out_raw.split_terminator('\n');
        let mut parsed_in_map: FxHashMap<String, u32> = FxHashMap::default();
        for line in out_parsed {
            let line: Vec<&str> = line.splitn(2, '\t').collect();
            parsed_in_map.insert(
                line[1].to_owned(),
                u32::from_str_radix(line[0], 16).unwrap(),
            );
        }

        assert_eq!(parsed_in_map.len(), 2, "Wrong number of lines on stdout");
        assert_eq!(
            match parsed_in_map.get(file_path.to_str().unwrap()) {
                None => {
                    panic!("Can't find first file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x38561ced,
            "First file wrong crc32."
        );
        assert_eq!(
            match parsed_in_map.get(file_path2.to_str().unwrap()) {
                None => {
                    panic!("Can't find second file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x07a9e748,
            "Second file wrong crc32."
        );

        assert!(out_err.is_empty(), "Something was written to stderr");

        //TEARDOWN
        match dir.close() {
            Ok(_) => {}
            Err(_) => {
                panic!("Error when deleting test file.")
            }
        };
    }

    #[test]
    fn test_directory_stdout_recursion() {
        //SETUP
        let mut out_std: Vec<u8> = Vec::new();
        let mut out_err: Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests") {
            Ok(dir) => dir,
            Err(e) => {
                panic!("Error when creating directory for unit test.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Test string\nIn test file".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let dir1 = dir.path().join("sub_folder1");
        match fs::create_dir(&dir1) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when creating test directory.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir1.join("unit-test-file2");
        let mut f = match File::create(&file_path2) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Second file :3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let dir2 = dir.path().join("sub_folder2");
        match fs::create_dir(&dir2) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when creating test directory.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0xb61a0e22
        let file_path3 = dir2.join("unit-test-file3");
        let mut f = match File::create(&file_path3) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Another file \\o/".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: None,
            buffer_size: 32,
            recursive: Recursive::Yes,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //TEST
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        let out_raw = String::from_utf8_lossy(&out_std).into_owned();

        let out_parsed = out_raw.split_terminator('\n');
        let mut parsed_in_map: FxHashMap<String, u32> = FxHashMap::default();
        for line in out_parsed {
            let line: Vec<&str> = line.splitn(2, '\t').collect();
            parsed_in_map.insert(
                line[1].to_owned(),
                u32::from_str_radix(line[0], 16).unwrap(),
            );
        }

        assert_eq!(parsed_in_map.len(), 3, "Wrong number of lines on stdout");
        assert_eq!(
            match parsed_in_map.get(file_path.to_str().unwrap()) {
                None => {
                    panic!("Can't find first file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x38561ced,
            "First file wrong crc32."
        );
        assert_eq!(
            match parsed_in_map.get(file_path2.to_str().unwrap()) {
                None => {
                    panic!("Can't find second file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x07a9e748,
            "Second file wrong crc32."
        );
        assert_eq!(
            match parsed_in_map.get(file_path3.to_str().unwrap()) {
                None => {
                    panic!("Can't find third file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0xb61a0e22,
            "Third file wrong crc32."
        );

        //TEARDOWN
        match dir.close() {
            Ok(_) => {}
            Err(_) => {
                panic!("Error when deleting test file.")
            }
        };
    }

    #[test]
    fn test_directory_output_file() {
        //SETUP
        let mut out_std: Vec<u8> = Vec::new();
        let mut out_err: Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests") {
            Ok(dir) => dir,
            Err(e) => {
                panic!("Error when creating directory for unit test.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Test string\nIn test file".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir.path().join("unit-test-file2");
        let mut f = match File::create(&file_path2) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Second file :3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: Some(dir.path().join("output")),
            buffer_size: 32,
            recursive: Recursive::No,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //TEST
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        let mut hashes = FxHashMap::default();
        match load_file(&mut hashes, &dir.path().join("output")) {
            None => {}
            Some(e) => {
                panic!("Error reading output hashes.\nError: {}", e);
            }
        };

        assert_eq!(hashes.len(), 2, "Wrong number of lines on stdout");
        assert_eq!(
            match hashes.get(file_path.to_str().unwrap()) {
                None => {
                    panic!("Can't find first file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x38561ced,
            "First file wrong crc32."
        );
        assert_eq!(
            match hashes.get(file_path2.to_str().unwrap()) {
                None => {
                    panic!("Can't find second file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x07a9e748,
            "Second file wrong crc32."
        );

        assert!(out_std.is_empty(), "Something was written to stdout");
        assert!(out_err.is_empty(), "Something was written to stderr");

        //TEARDOWN
        match dir.close() {
            Ok(_) => {}
            Err(_) => {
                panic!("Error when deleting test file.")
            }
        };
    }

    #[test]
    fn test_directory_output_file_recursion() {
        //SETUP
        let mut out_std: Vec<u8> = Vec::new();
        let mut out_err: Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests") {
            Ok(dir) => dir,
            Err(e) => {
                panic!("Error when creating directory for unit test.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Test string\nIn test file".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let dir1 = dir.path().join("sub_folder1");
        match fs::create_dir(&dir1) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when creating test directory.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir1.join("unit-test-file2");
        let mut f = match File::create(&file_path2) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Second file :3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let dir2 = dir.path().join("sub_folder2");
        match fs::create_dir(&dir2) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when creating test directory.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0xb61a0e22
        let file_path3 = dir2.join("unit-test-file3");
        let mut f = match File::create(&file_path3) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Another file \\o/".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: Some(dir.path().join("output")),
            buffer_size: 32,
            recursive: Recursive::Yes,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //TEST
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        let mut hashes = FxHashMap::default();
        match load_file(&mut hashes, &dir.path().join("output")) {
            None => {}
            Some(e) => {
                panic!("Error reading output hashes.\nError: {}", e);
            }
        };

        assert_eq!(hashes.len(), 3, "Wrong number of lines on stdout");
        assert_eq!(
            match hashes.get(file_path.to_str().unwrap()) {
                None => {
                    panic!("Can't find first file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x38561ced,
            "First file wrong crc32."
        );
        assert_eq!(
            match hashes.get(file_path2.to_str().unwrap()) {
                None => {
                    panic!("Can't find second file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x07a9e748,
            "Second file wrong crc32."
        );
        assert_eq!(
            match hashes.get(file_path3.to_str().unwrap()) {
                None => {
                    panic!("Can't find third file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0xb61a0e22,
            "Third file wrong crc32."
        );

        assert!(out_std.is_empty(), "Something was written to stdout");
        assert!(out_err.is_empty(), "Something was written to stderr");

        //TEARDOWN
        match dir.close() {
            Ok(_) => {}
            Err(_) => {
                panic!("Error when deleting test file.")
            }
        };
    }

    #[test]
    fn test_directory_output_file_mismatch() {
        //SETUP
        let mut out_std: Vec<u8> = Vec::new();
        let mut out_err: Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests") {
            Ok(dir) => dir,
            Err(e) => {
                panic!("Error when creating directory for unit test.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Test string\nIn test file".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir.path().join("unit-test-file2");
        let mut f = match File::create(&file_path2) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Second file :3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: Some(dir.path().join("output")),
            buffer_size: 32,
            recursive: Recursive::No,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //Create output file
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        //Modify file with crc32 hash 0x812651aa
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when rewriting file for test.\nError: {}", e);
            }
        };
        match f.write("Modified file <3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: Some(dir.path().join("output")),
            buffer_size: 32,
            recursive: Recursive::No,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //TEST
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        let mut hashes = FxHashMap::default();
        match load_file(&mut hashes, &dir.path().join("output")) {
            None => {}
            Some(e) => {
                panic!("Error reading output hashes.\nError: {}", e);
            }
        };

        assert_eq!(hashes.len(), 2, "Wrong number of lines on stdout");
        assert_eq!(
            match hashes.get(file_path.to_str().unwrap()) {
                None => {
                    panic!("Can't find first file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x812651aa,
            "First file wrong crc32."
        );
        assert_eq!(
            match hashes.get(file_path2.to_str().unwrap()) {
                None => {
                    panic!("Can't find second file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x07a9e748,
            "Second file wrong crc32."
        );

        let expected = format!(
            "File hash mismatch:\n\tFile: {}\n\tOld Hash: {}\n\tNew Hash: {}\n",
            file_path.to_str().unwrap(),
            "38561ced",
            "812651aa"
        );

        assert_eq!(out_err, expected.as_bytes());
        assert!(out_std.is_empty(), "Something was written to stdout");

        //TEARDOWN
        match dir.close() {
            Ok(_) => {}
            Err(_) => {
                panic!("Error when deleting test file.")
            }
        };
    }

    #[test]
    fn test_directory_output_file_recursion_mismatch() {
        //SETUP
        let mut out_std: Vec<u8> = Vec::new();
        let mut out_err: Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests") {
            Ok(dir) => dir,
            Err(e) => {
                panic!("Error when creating directory for unit test.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Test string\nIn test file".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let dir1 = dir.path().join("sub_folder1");
        match fs::create_dir(&dir1) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when creating test directory.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir1.join("unit-test-file2");
        let mut f = match File::create(&file_path2) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Second file :3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let dir2 = dir.path().join("sub_folder2");
        match fs::create_dir(&dir2) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when creating test directory.\nError: {}", e);
            }
        };

        //Create test file with crc32 hash 0xb61a0e22
        let file_path3 = dir2.join("unit-test-file3");
        let mut f = match File::create(&file_path3) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when creating file for test.\nError: {}", e);
            }
        };
        match f.write("Another file \\o/".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: Some(dir.path().join("output")),
            buffer_size: 32,
            recursive: Recursive::Yes,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //Create output file
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        //Modify file with crc32 hash 0x812651aa
        let mut f = match File::create(&file_path3) {
            Ok(file) => file,
            Err(e) => {
                panic!("Error when rewriting file for test.\nError: {}", e);
            }
        };
        match f.write("Modified file <3".as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error when writing to the test file.\nError: {}", e);
            }
        };

        let settings = Setting {
            input: Some(dir.path().to_path_buf()),
            output: Some(dir.path().join("output")),
            buffer_size: 32,
            recursive: Recursive::Yes,
            quiet: Quiet::Yes,
            verbose: Verbose::Nothing,
        };

        //TEST
        hashes_from_dir(&settings, &mut out_std, &mut out_err);

        let mut hashes = FxHashMap::default();
        match load_file(&mut hashes, &dir.path().join("output")) {
            None => {}
            Some(e) => {
                panic!("Error reading output hashes.\nError: {}", e);
            }
        };

        assert_eq!(hashes.len(), 3, "Wrong number of lines on stdout");
        assert_eq!(
            match hashes.get(file_path.to_str().unwrap()) {
                None => {
                    panic!("Can't find first file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x38561ced,
            "First file wrong crc32."
        );
        assert_eq!(
            match hashes.get(file_path2.to_str().unwrap()) {
                None => {
                    panic!("Can't find second file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x07a9e748,
            "Second file wrong crc32."
        );
        assert_eq!(
            match hashes.get(file_path3.to_str().unwrap()) {
                None => {
                    panic!("Can't find third file in output");
                }
                Some(value) => {
                    *value
                }
            },
            0x812651aa,
            "Third file wrong crc32."
        );

        let expected = format!(
            "File hash mismatch:\n\tFile: {}\n\tOld Hash: {}\n\tNew Hash: {}\n",
            file_path3.to_str().unwrap(),
            "b61a0e22",
            "812651aa"
        );

        assert_eq!(out_err, expected.as_bytes());
        assert!(out_std.is_empty(), "Something was written to stdout");

        //TEARDOWN
        match dir.close() {
            Ok(_) => {}
            Err(_) => {
                panic!("Error when deleting test file.")
            }
        };
    }
}
