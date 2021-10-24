# A SmokeLoader unpacker
This is a small repo demonstrating how to unpack malware with exe-rs!

To start the extraction, download the sample at [MalwareBazaar](https://bazaar.abuse.ch/sample/fd6996eab709c3ed21ef140958d9a9147902336b85b47bc896372a18e469a6fc/) and extract it to the `samples` directory in the repo. Then build and run the program. On success, you will be faced with a checksum for the 32- and 64-bit payloads this variant of SmokeLoader drops, along with the decrypted and extracted import table of the loader executable. 

*Be warned!* This executes benign functions in the malware-- rather than reverse engineering decompression algorithms, they were used directly! While this individual instance is technically safe, it's recommended for maximum safety to run this in a sandboxed environment. Similar functionality can be recreated with [unicorn-rs](https://crates.io/crates/unicorn) if you wish to simply emulate the code.

## Building

This repository expects a Windows host platform. Other platforms will require customization to run this properly.

Because we're executing functionality within the samples, we need to match the sample architecture, which is x86 32-bit up until the payloads. Your `cargo build` command should look like this:
    
`cargo build --target i686-pc-windows-msvc`

If you don't have that target, `rustup target add i686-pc-windows-msvc` should do the trick.

## Extracting

The various stages used to eventually get to the core SmokeLoader payload are all extracted in the `samples` directory. Stage 1 of this payload uses [TEA decryption](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) to load a stage 2 shellcode. Stage 2 decrypts and decompresses a stage 3 shellcode intended to inject the unpacked sample into a victim process. The unpacked sample contains two separate payloads which need to have their headers rebuilt. Their original formats are preserved when dumped.

The shellcode payloads are converted into PE files due to IDA Free refusing to disassemble anything that's not an executable format. Their original formats are preserved as well (although you'll have an annoying time with stage 2 if you don't get the offset to the entrypoint). A new helper function in exe-rs was used to create these executables.

During extraction, the decrypted import table of the loader is dumped to demonstrate new functionality in exe-rs, namely hashtable lookups of imports. This strategy can be applied to stage 2 as well, but you have limited hashes to look up.

## TODO

* briefly analyze the payloads like the loader stub
