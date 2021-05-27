extern crate crc32fast;
extern crate byte_unit;

use clap::{App, Arg};
use crc32fast::Hasher;
use same_file::is_same_file;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::{metadata, File, Metadata};
use std::io::{BufRead, ErrorKind, Read, Write, Error};
use std::path::{Path, PathBuf};
use std::{fs, io, process};
use std::time::Instant;
use byte_unit::Byte;

fn main() {
    let matches = App::new("Hashify")
        .version("1.3.2")
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

    let recursive: bool = matches.is_present("recursive");

    let quiet: bool = matches.is_present("quiet");

    let output: &str = matches.value_of("output").unwrap_or("");

    let verbose: u8 = match matches.occurrences_of("verbose") {
        0 => 0,
        1 => 1,
        2 | _ => 2,
    };

    let buffer_size: usize = matches
        .value_of("buffer")
        .unwrap_or("128")
        .parse::<usize>()
        .unwrap_or(128);

    //Read from stdin
    if input.is_empty() {
        let hash = match hash_from_input(io::stdin(), buffer_size){
            Ok(hash) => {hash}
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        };
        println!("{:08x}", hash);
    } else {
        //Read file or directory
        let metadata: Metadata = match metadata(input) {
            Ok(metadata) => metadata,
            Err(_) => {
                eprintln!("Input doesn't exit or insufficient permissions!");
                process::exit(1);
            }
        };

        //Input is a file
        if metadata.is_file() {
            match crc32_hash(PathBuf::from(input), buffer_size) {
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
            hashes_from_dir(buffer_size, recursive, output, input, verbose, quiet, &mut io::stdout(), &mut io::stderr());
        }
    }
}

//Calculate crc32 for given file
//Returns tuple (hash, read_bytes)
fn crc32_hash(input: PathBuf, buffer_size: usize) -> Result<(u32, u64), io::Error> {
    let mut hasher = Hasher::new();

    let mut read_bytes:u64 = 0;

    let mut f = File::open(input)?;
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
fn hash_from_input<R: Read>(mut input: R, buffer_size: usize) -> Result<u32, Error>{
    let mut hasher = Hasher::new();

    let temp_buffer: Vec<u8> = vec![0; 1024 * buffer_size];
    let mut buffer = temp_buffer.into_boxed_slice();
    let mut length = 1;

    while length > 0 {
        length = match input.read(&mut *buffer) {
            Ok(len) => len,
            Err(e) => {
                return Err(Error::new(e.kind(), format!("Error when reading from stdin: {}", e)));
            }
        };
        hasher.update(&buffer[..length]);
    }

    Ok(hasher.finalize())
}

//Calculate crc32 given directory
fn hashes_from_dir<WS: Write, WE: Write>(buffer_size: usize, recursive: bool, output:&str, input:&str, verbose:u8, quiet: bool, mut out_std: WS, mut out_err: WE){
    //Input is a directory
    let mut hashes: HashMap<String, u32> = HashMap::new();
    let mut hashes_old: HashMap<String, u32> = HashMap::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut directories: VecDeque<PathBuf> = VecDeque::new();
    directories.push_back(PathBuf::from(input));

    //Init stats
    let mut read_bytes: u64 = 0;
    let mut files_processed: u64 = 0;
    let mut files_added: u64 = 0;
    let mut files_removed: u64 = 0;
    let mut files_skipped: u64 = 0;
    let start_time = Instant::now();

    //Load hashes if exists
    if Path::new(output).exists() {
        match load_file(&mut hashes_old, output){
            None => {}
            Some(e) => {
                eprintln!("Error when loading hashes: {}", e);
                process::exit(1);
            }
        };
    }

    let output_path = Path::new(output);
    let output_file_name = output_path.file_name().unwrap_or(OsStr::new(""));

    //Iterate through directory/ies
    loop {
        if directories.is_empty() {
            break;
        } else {
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
                    let file_os_name =
                        file.path().as_os_str().to_string_lossy().into_owned();
                    if file_name.file_name().unwrap() == output_file_name
                        && is_same_file(&file_name, output_path).unwrap_or(false)
                    {
                        continue;
                    }
                    let (hash, read) = match crc32_hash(file_name, buffer_size) {
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
                        } else if verbose >= 2 {
                            writeln!(out_std,
                                "Known file found:\n\tFile: {}\n\tHash: {:08x}",
                                file_os_name, hash
                            ).unwrap();
                        }
                    } else{
                        files_added += 1;
                        if verbose >= 1 {
                            writeln!(out_std,
                                     "New file found:\n\tFile: {}\n\tHash: {:08x}",
                                     file_os_name, hash
                            ).unwrap();
                        }
                    }

                    read_bytes += read;
                    files_processed += 1;
                    hashes.insert(file_os_name, hash);
                } else if recursive && file.file_type().unwrap().is_dir() {
                    if !seen.contains(&file_name) {
                        seen.insert(file_name.clone());
                        directories.push_back(file_name);
                    }
                }
            }
        }
    }
    //Print to stdout if output file not specified
    if output == "" {
        for (file, hash) in hashes.iter() {
            writeln!(out_std,"{:08x}\t{}", hash, file).unwrap();
        }
    } else {
        //Write to file if output file specified
        let removed_iter = hashes_old.iter().filter(|x| !hashes.contains_key(x.0));
        for (file, hash) in removed_iter {
            files_removed += 1;
            if verbose >= 1 {
                writeln!(out_std,
                         "Removed file found:\n\tFile: {}\n\tHash: {:08x}",
                         file, hash
                ).unwrap();
            }
        }

        let mut f = match File::create(output) {
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
    if !quiet{
        let elapsed = start_time.elapsed();
        let size = Byte::from_bytes(read_bytes as u128);

        println!("Statistics of the runtime:");
        println!("\tElapsed time: {}:{}:{:.4}", elapsed.as_secs()/3600, elapsed.as_secs()/60, elapsed.as_secs_f32());
        println!("\tFiles processed: {}", files_processed);
        println!("\tBytes processed: {}", size.get_appropriate_unit(true));
        println!("\tNumber of new files: {}", files_added);
        println!("\tNumber of removed files: {}", files_removed);
        println!("\tSkipped files due to permissions: {}", files_skipped);
    }
}

//Load hashes into HashMap
fn load_file(hashes: &mut HashMap<String, u32>, file: &str) -> Option<io::Error> {
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
    return None
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_single_file() {
        //SETUP
        let dir = match TempDir::new("unit_tests"){
            Ok(dir) => {dir}
            Err(e) => {
                assert!(false, "Error when creating directory for unit test.\nError: {}", e);
                return;
            }
        };

        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Test string\nIn test file".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //TEST
        let hash = match crc32_hash(file_path.clone(), 32){
            Ok(hash) => {hash.0}
            Err(e) => {
                assert!(false, "{}",e);
                return;
            }
        };
        assert_eq!(0x38561ced, hash, "crc32 mismatch on test file.");

        //TEARDOWN
        match dir.close(){
            Ok(_) => {}
            Err(_) => {assert!(false, "Error when deleting test file.")}
        };
    }

    #[test]
    fn test_input_stream() {
        //SETUP
        let input = "Test string\nIn test file";

        //TEST
        let hash = match hash_from_input(input.as_bytes(), 32){
            Ok(hash) => {hash}
            Err(e) => {
                assert!(false, "{}",e);
                return;
            }
        };
        assert_eq!(0x38561ced, hash, "crc32 mismatch on input stream.");

    }

    #[test]
    fn test_directory_stdout() {
        //SETUP
        let mut out_std:Vec<u8> = Vec::new();
        let mut out_err:Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests"){
            Ok(dir) => {dir}
            Err(e) => {
                assert!(false, "Error when creating directory for unit test.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Test string\nIn test file".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir.path().join("unit-test-file2");
        let mut f = match File::create(&file_path2){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Second file :3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //TEST
        hashes_from_dir(32, false, "", &dir.path().as_os_str().to_string_lossy().into_owned(), 0, true, &mut out_std, &mut out_err);

        let out_raw = String::from_utf8_lossy(&out_std).into_owned();
        let out_parsed =out_raw.split_terminator("\n");
        let mut parsed_in_map:HashMap<String, u32> = HashMap::new();
        for line in out_parsed{
            let line: Vec<&str> = line.splitn(2, '\t').collect();
            parsed_in_map.insert(
                line[1].to_owned(),
                u32::from_str_radix(line[0], 16).unwrap(),
            );
        }

        assert_eq!(parsed_in_map.len(), 2, "Wrong number of lines on stdout");
        assert_eq!(match parsed_in_map.get(file_path.to_str().unwrap()){
            None => {
                assert!(false, "Can't find first file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x38561ced, "First file wrong crc32.");
        assert_eq!(match parsed_in_map.get(file_path2.to_str().unwrap()){
            None => {
                assert!(false, "Can't find second file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x07a9e748, "Second file wrong crc32.");

        assert!(out_err.is_empty(), "Something was written to stderr");

        //TEARDOWN
        match dir.close(){
            Ok(_) => {}
            Err(_) => {assert!(false, "Error when deleting test file.")}
        };

    }

    #[test]
    fn test_directory_stdout_recursion() {
        //SETUP
        let mut out_std:Vec<u8> = Vec::new();
        let mut out_err:Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests"){
            Ok(dir) => {dir}
            Err(e) => {
                assert!(false, "Error when creating directory for unit test.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Test string\nIn test file".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        let dir1 = dir.path().join("sub_folder1");
        match fs::create_dir(&dir1){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when creating test directory.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir1.join("unit-test-file2");
        let mut f = match File::create(&file_path2){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Second file :3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        let dir2 = dir.path().join("sub_folder2");
        match fs::create_dir(&dir2){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when creating test directory.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0xb61a0e22
        let file_path3 = dir2.join("unit-test-file3");
        let mut f = match File::create(&file_path3){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Another file \\o/".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };
        //TEST
        hashes_from_dir(32, true, "", &dir.path().as_os_str().to_string_lossy().into_owned(), 0,true, &mut out_std, &mut out_err);

        let out_raw = String::from_utf8_lossy(&out_std).into_owned();

        let out_parsed =out_raw.split_terminator("\n");
        let mut parsed_in_map:HashMap<String, u32> = HashMap::new();
        for line in out_parsed{
            let line: Vec<&str> = line.splitn(2, '\t').collect();
            parsed_in_map.insert(
                line[1].to_owned(),
                u32::from_str_radix(line[0], 16).unwrap(),
            );
        }

        assert_eq!(parsed_in_map.len(), 3, "Wrong number of lines on stdout");
        assert_eq!(match parsed_in_map.get(file_path.to_str().unwrap()){
            None => {
                assert!(false, "Can't find first file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x38561ced, "First file wrong crc32.");
        assert_eq!(match parsed_in_map.get(file_path2.to_str().unwrap()){
            None => {
                assert!(false, "Can't find second file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x07a9e748, "Second file wrong crc32.");
        assert_eq!(match parsed_in_map.get(file_path3.to_str().unwrap()){
            None => {
                assert!(false, "Can't find third file in output");
                return;
            }
            Some(value) => {*value}
        }, 0xb61a0e22, "Third file wrong crc32.");

        //TEARDOWN
        match dir.close(){
            Ok(_) => {}
            Err(_) => {assert!(false, "Error when deleting test file.")}
        };
    }

    #[test]
    fn test_directory_output_file() {
        //SETUP
        let mut out_std:Vec<u8> = Vec::new();
        let mut out_err:Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests"){
            Ok(dir) => {dir}
            Err(e) => {
                assert!(false, "Error when creating directory for unit test.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Test string\nIn test file".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir.path().join("unit-test-file2");
        let mut f = match File::create(&file_path2){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Second file :3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //TEST
        hashes_from_dir(32, false, dir.path().join("output").to_str().unwrap(), &dir.path().as_os_str().to_string_lossy().into_owned(), 0,true, &mut out_std, &mut out_err);

        let mut hashes = HashMap::new();
        match load_file(&mut hashes, dir.path().join("output").to_str().unwrap()){
            None => {}
            Some(e) => {
                assert!(false, "Error reading output hashes.\nError: {}", e);
                return;
            }
        };

        assert_eq!(hashes.len(), 2, "Wrong number of lines on stdout");
        assert_eq!(match hashes.get(file_path.to_str().unwrap()){
            None => {
                assert!(false, "Can't find first file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x38561ced, "First file wrong crc32.");
        assert_eq!(match hashes.get(file_path2.to_str().unwrap()){
            None => {
                assert!(false, "Can't find second file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x07a9e748, "Second file wrong crc32.");

        assert!(out_std.is_empty(), "Something was written to stdout");
        assert!(out_err.is_empty(), "Something was written to stderr");

        //TEARDOWN
        match dir.close(){
            Ok(_) => {}
            Err(_) => {assert!(false, "Error when deleting test file.")}
        };

    }

    #[test]
    fn test_directory_output_file_recursion() {
        //SETUP
        let mut out_std:Vec<u8> = Vec::new();
        let mut out_err:Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests"){
            Ok(dir) => {dir}
            Err(e) => {
                assert!(false, "Error when creating directory for unit test.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Test string\nIn test file".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        let dir1 = dir.path().join("sub_folder1");
        match fs::create_dir(&dir1){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when creating test directory.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir1.join("unit-test-file2");
        let mut f = match File::create(&file_path2){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Second file :3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        let dir2 = dir.path().join("sub_folder2");
        match fs::create_dir(&dir2){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when creating test directory.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0xb61a0e22
        let file_path3 = dir2.join("unit-test-file3");
        let mut f = match File::create(&file_path3){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Another file \\o/".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };
        //TEST
        hashes_from_dir(32, true, dir.path().join("output").to_str().unwrap(), &dir.path().as_os_str().to_string_lossy().into_owned(), 0,true, &mut out_std, &mut out_err);

        let mut hashes = HashMap::new();
        match load_file(&mut hashes, dir.path().join("output").to_str().unwrap()){
            None => {}
            Some(e) => {
                assert!(false, "Error reading output hashes.\nError: {}", e);
                return;
            }
        };

        assert_eq!(hashes.len(), 3, "Wrong number of lines on stdout");
        assert_eq!(match hashes.get(file_path.to_str().unwrap()){
            None => {
                assert!(false, "Can't find first file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x38561ced, "First file wrong crc32.");
        assert_eq!(match hashes.get(file_path2.to_str().unwrap()){
            None => {
                assert!(false, "Can't find second file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x07a9e748, "Second file wrong crc32.");
        assert_eq!(match hashes.get(file_path3.to_str().unwrap()){
            None => {
                assert!(false, "Can't find third file in output");
                return;
            }
            Some(value) => {*value}
        }, 0xb61a0e22, "Third file wrong crc32.");

        assert!(out_std.is_empty(), "Something was written to stdout");
        assert!(out_err.is_empty(), "Something was written to stderr");

        //TEARDOWN
        match dir.close(){
            Ok(_) => {}
            Err(_) => {assert!(false, "Error when deleting test file.")}
        };
    }

    #[test]
    fn test_directory_output_file_mismatch() {
        //SETUP
        let mut out_std:Vec<u8> = Vec::new();
        let mut out_err:Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests"){
            Ok(dir) => {dir}
            Err(e) => {
                assert!(false, "Error when creating directory for unit test.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Test string\nIn test file".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir.path().join("unit-test-file2");
        let mut f = match File::create(&file_path2){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Second file :3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //Create output file
        hashes_from_dir(32, false, dir.path().join("output").to_str().unwrap(), &dir.path().as_os_str().to_string_lossy().into_owned(), 0,true, &mut out_std, &mut out_err);

        //Modify file with crc32 hash 0x812651aa
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when rewriting file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Modified file <3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //TEST
        hashes_from_dir(32, false, dir.path().join("output").to_str().unwrap(), &dir.path().as_os_str().to_string_lossy().into_owned(), 0,true, &mut out_std, &mut out_err);


        let mut hashes = HashMap::new();
        match load_file(&mut hashes, dir.path().join("output").to_str().unwrap()){
            None => {}
            Some(e) => {
                assert!(false, "Error reading output hashes.\nError: {}", e);
                return;
            }
        };

        assert_eq!(hashes.len(), 2, "Wrong number of lines on stdout");
        assert_eq!(match hashes.get(file_path.to_str().unwrap()){
            None => {
                assert!(false, "Can't find first file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x812651aa, "First file wrong crc32.");
        assert_eq!(match hashes.get(file_path2.to_str().unwrap()){
            None => {
                assert!(false, "Can't find second file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x07a9e748, "Second file wrong crc32.");

        let expected = format!("File hash mismatch:\n\tFile: {}\n\tOld Hash: {}\n\tNew Hash: {}\n", file_path.to_str().unwrap(), "38561ced",  "812651aa");

        assert_eq!(out_err, expected.as_bytes());
        assert!(out_std.is_empty(), "Something was written to stdout");

        //TEARDOWN
        match dir.close(){
            Ok(_) => {}
            Err(_) => {assert!(false, "Error when deleting test file.")}
        };

    }

    #[test]
    fn test_directory_output_file_recursion_mismatch() {
        //SETUP
        let mut out_std:Vec<u8> = Vec::new();
        let mut out_err:Vec<u8> = Vec::new();

        //Create test dir
        let dir = match TempDir::new("unit_tests"){
            Ok(dir) => {dir}
            Err(e) => {
                assert!(false, "Error when creating directory for unit test.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x38561ced
        let file_path = dir.path().join("unit-test-file");
        let mut f = match File::create(&file_path){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Test string\nIn test file".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        let dir1 = dir.path().join("sub_folder1");
        match fs::create_dir(&dir1){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when creating test directory.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0x07a9e748
        let file_path2 = dir1.join("unit-test-file2");
        let mut f = match File::create(&file_path2){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Second file :3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        let dir2 = dir.path().join("sub_folder2");
        match fs::create_dir(&dir2){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when creating test directory.\nError: {}", e);
                return;
            }
        };

        //Create test file with crc32 hash 0xb61a0e22
        let file_path3 = dir2.join("unit-test-file3");
        let mut f = match File::create(&file_path3){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when creating file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Another file \\o/".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //Create output file
        hashes_from_dir(32, true, dir.path().join("output").to_str().unwrap(), &dir.path().as_os_str().to_string_lossy().into_owned(), 0,true, &mut out_std, &mut out_err);

        //Modify file with crc32 hash 0x812651aa
        let mut f = match File::create(&file_path3){
            Ok(file) => {file}
            Err(e) => {
                assert!(false, "Error when rewriting file for test.\nError: {}", e);
                return;
            }
        };
        match f.write("Modified file <3".as_bytes()){
            Ok(_) => {}
            Err(e) => {
                assert!(false, "Error when writing to the test file.\nError: {}", e);
                return;
            }
        };

        //TEST
        hashes_from_dir(32, true, dir.path().join("output").to_str().unwrap(), &dir.path().as_os_str().to_string_lossy().into_owned(), 0,true, &mut out_std, &mut out_err);

        let mut hashes = HashMap::new();
        match load_file(&mut hashes, dir.path().join("output").to_str().unwrap()){
            None => {}
            Some(e) => {
                assert!(false, "Error reading output hashes.\nError: {}", e);
                return;
            }
        };

        assert_eq!(hashes.len(), 3, "Wrong number of lines on stdout");
        assert_eq!(match hashes.get(file_path.to_str().unwrap()){
            None => {
                assert!(false, "Can't find first file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x38561ced, "First file wrong crc32.");
        assert_eq!(match hashes.get(file_path2.to_str().unwrap()){
            None => {
                assert!(false, "Can't find second file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x07a9e748, "Second file wrong crc32.");
        assert_eq!(match hashes.get(file_path3.to_str().unwrap()){
            None => {
                assert!(false, "Can't find third file in output");
                return;
            }
            Some(value) => {*value}
        }, 0x812651aa, "Third file wrong crc32.");

        let expected = format!("File hash mismatch:\n\tFile: {}\n\tOld Hash: {}\n\tNew Hash: {}\n", file_path3.to_str().unwrap(), "b61a0e22",  "812651aa");

        assert_eq!(out_err, expected.as_bytes());
        assert!(out_std.is_empty(), "Something was written to stdout");

        //TEARDOWN
        match dir.close(){
            Ok(_) => {}
            Err(_) => {assert!(false, "Error when deleting test file.")}
        };
    }
}