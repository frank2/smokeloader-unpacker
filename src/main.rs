use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
    
use exe::*;

use lazy_static;

use std::io::Cursor;

lazy_static::lazy_static! {
    static ref SAMPLE_HASH: String = "fd6996eab709c3ed21ef140958d9a9147902336b85b47bc896372a18e469a6fc".to_string();
    static ref SAMPLE_PATH: String = "samples".to_string();
    static ref SAMPLE: String = format!("{}/{}.exe", *SAMPLE_PATH, *SAMPLE_HASH);
    
    static ref STAGE2_BIN: String = format!("{}/stage2.bin", *SAMPLE_PATH);
    static ref STAGE2_EXE: String = format!("{}/stage2.exe", *SAMPLE_PATH);

    static ref STAGE3_BIN: String = format!("{}/stage3.bin", *SAMPLE_PATH);
    static ref STAGE3_EXE: String = format!("{}/stage3.exe", *SAMPLE_PATH);

    static ref UNPACKED: String = format!("{}/unpacked.exe", *SAMPLE_PATH);

    static ref DECRYPTED: String = format!("{}/decrypted.exe", *SAMPLE_PATH);
        
    static ref PAYLOAD32: String = format!("{}/payload32.bin", *SAMPLE_PATH);
    static ref PAYLOAD64: String = format!("{}/payload64.bin", *SAMPLE_PATH);
    static ref PAYLOAD32_DLL: String = format!("{}/payload32.dll", *SAMPLE_PATH);
    static ref PAYLOAD64_DLL: String = format!("{}/payload64.dll", *SAMPLE_PATH);
}

pub fn stage1_tea_decrypt(data: &Vec<u8>, key: &Vec<u32>) -> Vec<u8> {
    if key.len() != 4 { panic!("bad TEA key"); }

    let mut result = Vec::<u8>::new();
    let mut reader = Cursor::new(data);

    for _ in (0..data.len()).step_by(8) {
        let mut v0 = reader.read_u32::<LittleEndian>().unwrap();
        let mut v1 = reader.read_u32::<LittleEndian>().unwrap();
        let mut sum = 0xC6EF3720u32;
        let delta = 0x9E3779B9u32;
            
        let k0 = key[0];
        let k1 = key[1];
        let k2 = key[2];
        let k3 = key[3];

        for _ in 0..32 {
            let v1_p1 = (v0 << 4).wrapping_add(k2);
            let v1_p2 = v0.wrapping_add(sum);
            let v1_p3 = (v0 >> 5).wrapping_add(k3);
            v1 = v1.wrapping_sub(v1_p1 ^ v1_p2 ^ v1_p3);

            let v0_p1 = (v1 << 4).wrapping_add(k0);
            let v0_p2 = v1.wrapping_add(sum);
            let v0_p3 = (v1 >> 5).wrapping_add(k1);
            v0 = v0.wrapping_sub(v0_p1 ^ v0_p2 ^ v0_p3);

            sum = sum.wrapping_sub(delta);
        }

        result.write_u32::<LittleEndian>(v0).ok();
        result.write_u32::<LittleEndian>(v1).ok();
    }

    result
}

fn stage1() {
    let image = PEImage::from_disk_file(&*SAMPLE).unwrap();
        
    let shellcode_size = 0xF548usize;
    let shellcode_rva = RVA(0x7c10);
    let key_rva = RVA(0x3bec0);
        
    let shellcode = image.read(shellcode_rva.as_offset(&image.pe).unwrap(), shellcode_size).unwrap().to_vec();
    let key = image.get_slice_ref::<u32>(key_rva.as_offset(&image.pe).unwrap(), 4).unwrap().to_vec();

    let decrypted_shellcode = stage1_tea_decrypt(&shellcode, &key);
    std::fs::write(&*STAGE2_BIN, decrypted_shellcode.as_slice()).ok();

    let dumped_shellcode = PEImage::from_assembly(Arch::X86, decrypted_shellcode.as_slice(), Offset(0x3c0e)).unwrap();
    dumped_shellcode.save_as(&*STAGE2_EXE).ok();
}

pub fn stage2_hash(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut result = 0u32;

    for byte in bytes {
        result += (byte | 0x60) as u32;
        result <<= 1;
    }

    result
}

pub fn stage2_rnd_decrypt(data: &Vec<u8>) -> Vec<u8> {
    let mut seed = 0x80000001u32;
    let mut result = data.clone();

    // this is apparently just an rng algorithm used to encrypt data
    for i in 0..data.len() {
        seed = seed.wrapping_mul(0x343fd);
        seed = seed.wrapping_add(0x269ec3);

        let seed_result = (seed >> 0x10) as u8;
        result[i] ^= seed_result;
    }
    
    result
}

fn stage2() {
    let image = PEImage::from_disk_file(&*STAGE2_EXE).unwrap();

    /* there was a very brief interaction with a hash algorithm, but it only loaded LoadLibrary and GetProcAddress.
     * you can see for yourself by uncommenting this:

    let kernel32 = PEImage::from_disk_file("C:/Windows/System32/kernel32.dll").unwrap();
    let kernel32_export = ExportDirectory::parse(&kernel32.pe).unwrap();
    println!("{:?}", kernel32_export.get_export_name_by_hash::<u32>(&kernel32.pe, stage2_hash, 0x348bfa).unwrap());

     */
    
    let meta_data_rva = RVA(0x5413);
    let payload_data = RVA(0x5450);

    let payload_size = *meta_data_rva.as_offset(&image.pe).unwrap().get_ref::<u32>(&image.pe).unwrap() as usize;
    let payload = image.read(payload_data.as_offset(&image.pe).unwrap(), payload_size).unwrap().to_vec();
    let decrypted_payload = stage2_rnd_decrypt(&payload);

    let mut decompressed_size = *RVA(0x541c).as_offset(&image.pe).unwrap().get_ref::<u32>(&image.pe).unwrap();
    let mut decompressed = vec![0u8; decompressed_size as usize];

    // execute the decompression function in the stage2 shellcode
    let loaded = image.pe.load_image().unwrap();
    let decomp_ptr = RVA(0x5100).as_ptr(&loaded).unwrap();
    type DecompressShellcode = unsafe extern "cdecl" fn(*const u8, u32, *mut u8, *mut u32, u32);
    let decomp_fn = unsafe { std::mem::transmute::<*const u8,DecompressShellcode>(decomp_ptr) };

    unsafe { decomp_fn(decrypted_payload.as_ptr(),
                       decrypted_payload.len() as u32,
                       decompressed.as_mut_ptr(),
                       &mut decompressed_size as *mut u32,
                       0); }

    std::fs::write(&*STAGE3_BIN, decompressed.as_slice()).ok();

    let stage3_image = PEImage::from_assembly(Arch::X86, decompressed.as_slice(), Offset(0)).unwrap();
    stage3_image.save_as(&*STAGE3_EXE).ok();
}

fn stage3() {
    let image = PEImage::from_disk_file(&*STAGE3_EXE).unwrap();

    let embedded = image.pe.find_embedded_images(PEType::Disk);
    embedded[0].buffer.save(&*UNPACKED).ok();
}

fn unpacked_payload_data(arch: Arch) -> (RVA, usize) {
    match arch {
        Arch::X86 => (RVA(0x3016), 0x22ffusize),
        Arch::X64 => (RVA(0x5315), 0x2e60usize),
    }
}

// this function is responsible for decrypting code in the binary
fn unpacked_function_decrypt(pe: &mut PE, rva: RVA, size: usize) {
    let key = 0xadu8; // 0x9a96f7ad
    let mut ptr = rva.as_ptr(pe).unwrap() as *mut u8;

    for _ in 0..size {
        unsafe { *ptr ^= key };
        ptr = unsafe { ptr.add(1) };
    }
}

// this function is responsible for decrypting data, such as the payloads and import tables
fn unpacked_data_decrypt(pe: &mut PE, rva: RVA, size: usize) {
    let key = 0x9a96f7adu32;
    let mut ptr_u32 = rva.as_ptr(pe).unwrap() as *mut u32;
    let fixed_size = size >> 2; // divide by 4

    for _ in 0..fixed_size {
        unsafe { *ptr_u32 ^= key };
        ptr_u32 = unsafe { ptr_u32.add(1) };
    }
    
    let extra_size = size & 3;
    if extra_size == 0 { return; }

    let mut ptr_u8 = ptr_u32 as *mut u8;

    for _ in 0..extra_size {
        unsafe { *ptr_u8 ^= (key & 0xFF) as u8 };
        ptr_u8 = unsafe { ptr_u8.add(1) };
    }
}

// the loader aspect of smokeloader uses a custom version of djb2 with a different init constant
// to calculate a checksum for the payloads
pub fn unpacked_djb2_custom(init: u32, data: &Vec<u8>) -> u32 {
    let mut result = init;

    for byte in data {
        result = result.wrapping_add(result << 5);
        result = result.wrapping_add(*byte as u32);
    }

    result
}

pub fn unpacked_djb2(data: &Vec<u8>) -> u32 {
    unpacked_djb2_custom(0x1505, data)
}

pub fn unpacked_import_hash(s: &str) -> u32 {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);

    unpacked_djb2(&bytes)
}

fn unpacked_decrypt_image(pe: &mut PE) {
    unpacked_data_decrypt(pe, RVA(0x2f66), 0xB0); // various import hashes
    unpacked_data_decrypt(pe, RVA(0x3016), 0x22ff); // 32-bit payload
    unpacked_data_decrypt(pe, RVA(0x5315), 0x2e60); // 64-bit payload

    unpacked_function_decrypt(pe, RVA(0x125b), 0x51); // encryption/decryption function code
    unpacked_function_decrypt(pe, RVA(0x292f), 0x70); // code stage
    unpacked_function_decrypt(pe, RVA(0x2894), 0x58); // LoadImportsByHashList function
    unpacked_function_decrypt(pe, RVA(0x27be), 0x9a); // LoadImportByHash function
    unpacked_function_decrypt(pe, RVA(0x29c8), 0xa6); // dll loader
    unpacked_function_decrypt(pe, RVA(0x272c), 0x51); // LoadDLLByName function
    unpacked_function_decrypt(pe, RVA(0x2a9b), 0x99); // post-dll loader
    unpacked_function_decrypt(pe, RVA(0x1dce), 0x86); // CheckForRussianOrUkranianLanguage function
    unpacked_function_decrypt(pe, RVA(0x2b63), 0xae); // post-keyboard check functionality
    unpacked_function_decrypt(pe, RVA(0x1931), 0x1bb); // RerunIfBadIntegrity function
    unpacked_function_decrypt(pe, RVA(0x255b), 0x192); // LoadNTDLLFromDiskAndReimport function
    unpacked_function_decrypt(pe, RVA(0x1e9b), 0x71); // CheckProcessName function
    unpacked_function_decrypt(pe, RVA(0x21c2), 0x8a); // CheckIfDebuggerPresent function
    unpacked_function_decrypt(pe, RVA(0x2291), 0x283); // CheckForHookLibraries function
    unpacked_function_decrypt(pe, RVA(0x1f4f), 0x230); // CheckForVirtualizationSoftware function
    unpacked_function_decrypt(pe, RVA(0x1b25), 0x52); // towlower wrapper
    unpacked_function_decrypt(pe, RVA(0x1cb4), 0xd8); // CheckForVirtualizationDLLs function
    unpacked_function_decrypt(pe, RVA(0x1894), 0x59); // UnpackAndLoad function
    unpacked_function_decrypt(pe, RVA(0x140f), 0x8e); // DecryptAndDecompressData function
    unpacked_function_decrypt(pe, RVA(0x12e4), 0xe4); // DecompressData function
}

fn unpacked_dump_hashes(img: &PE, dll: &PE, rva: RVA) {
    let export_directory = ExportDirectory::parse(dll).unwrap();
    let mut ptr = rva.as_ptr(img).unwrap() as *const u32;
    let mut offset = rva.0; // redundant, but makes it easier to print the offset

    while unsafe { *ptr != 0 } {
        println!("+{:#x}: {}",
                 offset - 0x2f66,
                 export_directory.get_export_name_by_hash(dll,
                                                          unpacked_import_hash,
                                                          unsafe { *ptr }).unwrap().unwrap());
        ptr = unsafe { ptr.add(1) };
        offset += 4;
    }
}

fn unpacked_dump_imports(pe: &PE) {
    println!("Smokeloader imports:");
        
    let ntdll = PEImage::from_disk_file("C:/Windows/System32/ntdll.dll").unwrap();
    unpacked_dump_hashes(pe, &ntdll.pe, RVA(0x2f66));

    let kernel32 = PEImage::from_disk_file("C:/Windows/System32/kernel32.dll").unwrap();
    unpacked_dump_hashes(pe, &kernel32.pe, RVA(0x2f7e));

    let user32 = PEImage::from_disk_file("C:/Windows/System32/user32.dll").unwrap();
    unpacked_dump_hashes(pe, &user32.pe, RVA(0x2faa));

    let advapi32 = PEImage::from_disk_file("C:/Windows/System32/advapi32.dll").unwrap();
    unpacked_dump_hashes(pe, &advapi32.pe, RVA(0x2fc2));

    let shell32 = PEImage::from_disk_file("C:/Windows/System32/shell32.dll").unwrap();
    unpacked_dump_hashes(pe, &shell32.pe, RVA(0x2fce));

    unpacked_dump_hashes(pe, &ntdll.pe, RVA(0x2fd6));
}

fn unpacked_dump_payload(pe: &mut PE, arch: Arch) {
    let (rva, size) = unpacked_payload_data(arch);

    unpacked_data_decrypt(pe, rva, size);

    let size_ptr = rva.as_ptr(&pe).unwrap() as *const u32;
    let data_ptr = unsafe { size_ptr.add(1) as *const u8 };
    let mut decompressed_vec = vec![0u8; unsafe { *size_ptr as usize }];
        
    let decompress_ptr = RVA(0x12b2).as_ptr(&pe).unwrap();
    type DecompressData = unsafe extern "system" fn(*const u8, *mut u8);
    let decompress_fn = unsafe { std::mem::transmute::<*const u8, DecompressData>(decompress_ptr) };

    unsafe { decompress_fn(data_ptr, decompressed_vec.as_mut_ptr()) };

    // re-encrypt the data in the image
    unpacked_data_decrypt(pe, rva, size);

    // dump the raw payload to disk for preservation purposes
    match arch {
        Arch::X86 => std::fs::write(&*PAYLOAD32, decompressed_vec.as_slice()).ok(),
        Arch::X64 => std::fs::write(&*PAYLOAD64, decompressed_vec.as_slice()).ok(),
    };

    // the PE headers are erased, so recreate the headers and dump the file to disk
    let mut new_image = PEImage::from_disk_data(decompressed_vec.as_slice());
    let e_lfanew = *new_image.get_ref::<u32>(Offset(0)).unwrap();

    new_image.write_ref::<ImageDOSHeader>(Offset(0), &ImageDOSHeader::default()).ok();
    
    let mut dos_header = new_image.pe.get_mut_dos_header().unwrap();
    dos_header.e_lfanew = Offset(e_lfanew);

    let mut nt_header = new_image.pe.get_mut_nt_headers_32().unwrap();
    nt_header.signature = NT_SIGNATURE;

    match arch {
        Arch::X86 => new_image.save_as(&*PAYLOAD32_DLL).ok(),
        Arch::X64 => new_image.save_as(&*PAYLOAD64_DLL).ok(),
    };
}

fn unpacked_payload_checksum(pe: &PE, arch: Arch) -> u32 {
    let (rva, size) = unpacked_payload_data(arch);
    let data = rva.as_offset(pe).unwrap().read(pe, size).unwrap().to_vec();

    unpacked_djb2_custom(0x2260, &data)
}
        
fn unpacked() {
    let image = PEImage::from_disk_file(&*UNPACKED).unwrap();
    let mut decrypted = image.clone();
    let mut aslr = image.clone();

    println!("payload32 checksum: {:#x}", unpacked_payload_checksum(&image.pe, Arch::X86));
    assert_eq!(unpacked_payload_checksum(&image.pe, Arch::X86), 0xE49A84CB);
        
    println!("payload64 checksum: {:#x}\n", unpacked_payload_checksum(&image.pe, Arch::X64));
    assert_eq!(unpacked_payload_checksum(&image.pe, Arch::X64), 0x6BF204F4);

    unpacked_decrypt_image(&mut decrypted.pe);
    decrypted.save_as(&*DECRYPTED).ok();
        
    unpacked_dump_imports(&decrypted.pe);

    // we can turn on aslr because the code is written with a dynamic base in mind already
    match aslr.pe.get_valid_mut_nt_headers() {
        Ok(ref mut h) => match h {
            NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.dll_characteristics |= DLLCharacteristics::DYNAMIC_BASE,
            NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.dll_characteristics |= DLLCharacteristics::DYNAMIC_BASE,
        },
        Err(e) => panic!("error: {}", e),
    }

    let mut loaded_image = aslr.pe.load_image().unwrap();

    unpacked_dump_payload(&mut loaded_image, Arch::X86);
    unpacked_dump_payload(&mut loaded_image, Arch::X64);
}

fn main() {
    stage1();
    stage2();
    stage3();
    unpacked();
}
