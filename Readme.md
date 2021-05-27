Hashify\
Dominik 'Rengyr' Kosík <of@rengyr.eu>\
CRC32 hash.\
\
[![Project status](https://github.com/Rengyr/hashify/actions/workflows/rust.yml/badge.svg)](https://github.com/Rengyr/hashify/actions/workflows/rust.yml)

```
USAGE:
    hashify.exe [FLAGS] [OPTIONS] [input]

FLAGS:
    -h, --help         Prints help information
    -r, --recursive    Enable recursive search
	-q, --quiet        Disable statistics at the end
    -V, --version      Prints version information
    -v                 Sets the level of verbosity: (repeat for increased verbosity)
                        Level 0: No verbose info
                        Level 1: Verbose info about new/removed files
                        Level 2: Verbose info about every file


OPTIONS:
    -b, --buffer <buffer>    Size of read buffer in KB
    -o, --output <output>    Output of hash file
                             Its hash is ignored
                             Output is ignored for single file hash

ARGS:
    <input>    Input file or directory
```
