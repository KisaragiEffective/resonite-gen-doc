mod model;

use core::mem::size_of;
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::mem::{MaybeUninit, size_of_val, transmute};
use crate::model::{CoffRawSectionTableEntry, DataDirectory, NtAdditionalRawCoffHeaderField, PortableExecutableFormat, RawCoffField, RawCoffHeader, UsualDataDirectory, RawDosHeader, StandardCoffField, ClrMetadata, ImageDataDirectory};

fn main() {
    let x = BufReader::new(File::open("/home/kisaragi/.local/share/Steam/steamapps/common/Resonite/Resonite_Data/Managed/MessagePack.dll").expect("shit"));

    let hi = read_pe_file(x).expect("shit");

    println!("{hi:?}");
}


fn read_pe_file<R: Read + Seek>(mut reader: R) -> Result<PortableExecutableFormat, Cow<'static, str>> {

    let dos = {
        const DOS_HEADER_BYTES: usize = size_of::<RawDosHeader>();

        let mut buf = [0; DOS_HEADER_BYTES];
        let read_size = reader.read(&mut buf).map_err(|e| format!("I/O error: {e}"))?;
        if read_size != DOS_HEADER_BYTES {
            return Err(Cow::Borrowed("too short input for MS-DOS header"))
        }

        let raw_dos: RawDosHeader = RawDosHeader::new(buf);

        println!("[DEBUG] [DOS] {raw_dos:?}");

        const MZ_MAGIC: u16 = 0x4D5A;
        if raw_dos.__magic != MZ_MAGIC {
            return Err(Cow::Borrowed("invalid signature for DOS header"))
        }

        let lfa_new = raw_dos.lfanew;
        println!("DOS frame indicates PE starts from {lfa_new}");
        reader.seek(SeekFrom::Start(lfa_new as u64)).map_err(|e| format!("I/O error: {e}"))?;

        raw_dos
    };

    let coff_header = {
        const COFF_HEADER_SIZE: usize = size_of::<RawCoffHeader>();

        let mut buf = [0; COFF_HEADER_SIZE];
        let read_size = reader.read(&mut buf).map_err(|e| format!("I/O error: {e}"))?;
        if read_size != COFF_HEADER_SIZE {
            return Err(Cow::Owned(format!("too short input for COFF header: only {read_size} bytes were read")))
        }

        let mut raw_coff_header: RawCoffHeader = RawCoffHeader::new(buf);
        println!("[DEBUG] [COFF] {raw_coff_header:?}");

        const PE_MAGIC: u32 = 0x50450000;

        if raw_coff_header.sig != PE_MAGIC {
            return Err(Cow::Owned(format!("input is not a PE: the header value does not imply that it is PE: {sig:08X}", sig = raw_coff_header.sig)))
        }

        raw_coff_header
    };

    let standard_coff_field = {
        const STD_COFF_FIELD_SIZE: usize = size_of::<RawCoffField>();

        let mut buf = [0; STD_COFF_FIELD_SIZE];

        let read_size = reader.read(&mut buf).map_err(|e| format!("I/O error: {e}"))?;
        if read_size != STD_COFF_FIELD_SIZE {
            return Err(Cow::Borrowed("too short input for Raw COFF field"))
        }

        let raw_standard_header: RawCoffField = RawCoffField::new(buf);

        println!("[DEBUG] [COFF.STANDARD] {raw_standard_header:?}");

        raw_standard_header.bake().map_err(|_| Cow::Borrowed("COFF standard: bake failed"))?
    };

    let nt = {
        const NT_HEADER_SIZE: usize = size_of::<NtAdditionalRawCoffHeaderField>();

        let mut buf = [0; NT_HEADER_SIZE];
        let read_size = reader.read(&mut buf).map_err(|e| format!("I/O error: {e}"))?;
        if read_size != NT_HEADER_SIZE {
            return Err(Cow::Borrowed("too short input for NT header"))
        }

        let raw_nt_header: NtAdditionalRawCoffHeaderField = unsafe { transmute(buf) };

        if raw_nt_header.number_of_rva_and_sizes != 16 {
            return Err(Cow::Borrowed("unsupported DataDirectory length was detected: this is implementation restriction:\
            not supported other than regular-16 entries."))
        }

        raw_nt_header
    };

    println!("{nt:?}");

    let dd = {
        const DATA_DIRECTORY_SIZE: usize = size_of::<UsualDataDirectory>();
        let dd = {
            let mut buf = [0; DATA_DIRECTORY_SIZE];
            let read_size = reader.read(&mut buf).map_err(|e| format!("I/O error: {e}"))?;
            if read_size != DATA_DIRECTORY_SIZE {
                return Err(Cow::Borrowed("too short input for data directory"));
            }

            let raw_data_directory: UsualDataDirectory = unsafe { transmute(buf) };

            println!("[RVA] got: {raw_data_directory:#?}");

            raw_data_directory
        };

        let dd = dd.bake().map_err(|e| Cow::Owned(format!("baking of DataDirectory was failed; invalid padding: {e}")))?;

        dd
    };

    println!("{dd:?}");

    let section_count = coff_header.number_of_sections as usize;
    let mut image_section_header = Vec::with_capacity(section_count);

    for _ in 0..section_count {
        const SECTION_TABLE_ENTRY_SIZE: usize = size_of::<CoffRawSectionTableEntry>();

        let mut buf = [0; SECTION_TABLE_ENTRY_SIZE];
        let read_size = reader.read(&mut buf).map_err(|e| format!("I/O Error: {e}"))?;

        if read_size != SECTION_TABLE_ENTRY_SIZE {
            return Err(Cow::Borrowed("too short input for data directory"))
        }

        let raw_section_table_entry: CoffRawSectionTableEntry = unsafe { transmute(buf) };

        println!("[DEBUG] [COFF] [SECTION] {:?} was read", raw_section_table_entry.name);
        image_section_header.push(raw_section_table_entry);
    }

    println!("{image_section_header:#?}");

    println!("{:?}", image_section_header.iter().filter_map(|x| x.name.as_str().ok()).collect::<Vec<_>>());
    let dotnet_metadata: Option<ClrMetadata> = if let Some(text_section) = image_section_header.iter().find(|x| x.name.as_str().ok() == Some(".text")) {
        println!("[CLR] try: decoding Cor20 metadata");
        'read: {
            // TODO: what is leading 8-bytes???
            let cor20_starting_pos = text_section.pointer_to_raw_data + 8;
            println!("[CLR] note: head is assumed on: {cor20_starting_pos:08x}");
            reader.seek(SeekFrom::Start(cor20_starting_pos as u64)).expect("seek error");

            let header = {
                #[repr(C)]
                #[derive(Debug)]
                struct Cor20Header {
                    __cb: u32,
                    major_runtime: u16,
                    minor_runtime: u16,
                    metadata: ImageDataDirectory,
                    flags: u32,
                    entry_point_token_or_rva: u32,
                    resources: ImageDataDirectory,
                    strong_name_signature: ImageDataDirectory,
                    code_manager_table: ImageDataDirectory,
                    vtable_fixups: ImageDataDirectory,
                    export_address_table_jumps: ImageDataDirectory,
                }

                const COR20_HEADER_SIZE: usize = size_of::<Cor20Header>();

                let mut buf = [0; COR20_HEADER_SIZE];

                let size = reader.read(&mut buf);

                let size = match size {
                    Ok(size) => { size }
                    Err(_) => break 'read None
                };

                if size != COR20_HEADER_SIZE {
                    break 'read None
                }

                println!("[CLR] raw: {buf:?}");
                let header: Cor20Header = unsafe { transmute(buf) };
                println!("[CLR] raw: {header:?}");

                println!("[CLR] major = {major}, minor = {minor}", major = header.major_runtime, minor = header.minor_runtime);

                header
            };
            let metadata = header.metadata;

            println!("[CLR] found CLR metadata: {m:?}", m = metadata);
            let resolved_file_offset = metadata.relative_virtual_address.0 - standard_coff_field.base_of_code.0 + text_section.pointer_to_raw_data;
            println!("[CLR] resolved offset: {resolved_file_offset:08X}");

            let Ok(_) = reader.seek(SeekFrom::Start(resolved_file_offset as u64)) else {
                break 'read None
            };

            // now reader should be on CLI metadata beginning

            // TODO: decode CLI metadata and generate documentation
            struct MetadataHeader {
                signature: u32,
                major: u16,
                minor: u16,
                __reserved: u32,
                version: String,
                flags: u16,
                number_of_streams: u16,
            }

            let mut pre = [0; 16];

            reader.read_exact(&mut pre).expect("oh no");

            let (signature, major, minor, __reserved, utf8_length) = (
                u32::from_le_bytes(pre[0..4].try_into().unwrap()),
                u16::from_le_bytes(pre[4..6].try_into().unwrap()),
                u16::from_le_bytes(pre[6..8].try_into().unwrap()),
                u32::from_le_bytes(pre[8..12].try_into().unwrap()),
                u32::from_le_bytes(pre[12..16].try_into().unwrap()),
            );

            println!("{signature:08X} | {major:04X} | {minor:04X} | {__reserved:08X} | {utf8_length:08X}");
            println!("version length as UTF-8 codepoints: {utf8_length}");
            println!("starting from {:08X}", resolved_file_offset as usize + size_of_val(&pre));

            let mut version = vec![0; utf8_length as usize];

            reader.read_exact(&mut version).expect("ohhhhh");
            println!("raw buffer: {version:?}");
            let decoded = String::from_utf8(version).expect("illegal UTF-8 sequence for compiler version was committed by a compiler");

            println!("version information: {decoded}");

            None

            // Some(todo!())
        }
    } else {
        println!("[CLI] try: this DLL does not have CLI metadata, skipping detection");
        None
    };
    Ok(PortableExecutableFormat {
        dos,
        dos_stub: vec![],
        coff: standard_coff_field,
        nt,
        dotnet: dotnet_metadata,
    })
}