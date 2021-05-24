Hashify 1.2.1
Dominik 'Rengyr' Kosík <of@rengyr.eu>
CRC32 hash.

USAGE:
    hashify [FLAGS] [OPTIONS] [input]

FLAGS:
    -h, --help         Prints help information
    -r, --recursive    Enable recursive search
    -V, --version      Prints version information

OPTIONS:
    -b, --buffer <buffer>    Size of read buffer in KB
    -o, --output <output>    Output of hash file
                             Its hash is ignored
                             Output is ignored for single file hash

ARGS:
    <input>    Input file or directory