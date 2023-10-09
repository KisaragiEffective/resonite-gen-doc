mod model;
mod cor20;

use core::mem::size_of;
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::mem::{size_of_val, transmute};
use std::num::NonZeroU32;
use std::path::PathBuf;
use clap::Parser;
use crate::cor20::{Cor20Header, MetadataHeader, StreamHeader, StreamSize, SharpTilde, PartialRowCountCollection, PredefinedRowCollection, Module};
use crate::model::{CoffRawSectionTableEntry, NtAdditionalRawCoffHeaderField, PortableExecutableFormat, RawCoffField, RawCoffHeader, UsualDataDirectory, RawDosHeader, ClrMetadata};

#[derive(Parser)]
struct Decode {
    path: PathBuf,
}

fn main() {
    let args = Decode::parse();
    let x = BufReader::new(File::open(args.path).expect("IO error"));

    let hi = read_pe_file(x).expect("failed to decode");

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

        let raw_coff_header: RawCoffHeader = RawCoffHeader::new(buf);
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

        

        dd.bake().map_err(|e| Cow::Owned(format!("baking of DataDirectory was failed; invalid padding: {e}")))?
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
            let version = String::from_utf8(version).expect("illegal UTF-8 sequence for compiler version was committed by a compiler");

            println!("version information: {version}");

            let mut buf = [0; 4];

            reader.read_exact(&mut buf).expect("failed");

            let (flags, number_of_streams) = (
                u16::from_le_bytes(buf[0..2].try_into().unwrap()),
                u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            );

            let _header = MetadataHeader {
                signature,
                major,
                minor,
                __reserved,
                version,
                flags,
                number_of_streams,
            };

            let mut stream_header: Vec<StreamHeader> = Vec::with_capacity(number_of_streams as usize);

            for i in 0..number_of_streams {
                println!("[CLR] decoding stream #{i}");
                let mut size_buf = [0; size_of::<StreamSize>()];
                reader.read_exact(&mut size_buf).expect("failed to read stream size");

                let stream_size: StreamSize = StreamSize {
                    offset_from_metadata_header: u32::from_le_bytes(size_buf[0..4].try_into().unwrap()),
                    size: u32::from_le_bytes(size_buf[4..8].try_into().unwrap()),
                };

                // println!("    size: {stream_size:?}");

                let mut temporal_buffer = [0; 32];

                let backed_up = reader.stream_position().expect("failed to get current position");
                // println!("    current loc: {backed_up:08X}");

                let name = 'find_stream_name: loop {
                    let mut stream_name = String::with_capacity(32);

                    let actual_read_size = reader.read(&mut temporal_buffer).expect("cannot find Stream name");

                    if let Some((terminated, _)) = temporal_buffer[0..actual_read_size].iter().enumerate().find(|(_, x)| **x == 0) {
                        let show = &temporal_buffer[0..terminated];
                        // println!("    terminated: {show:?}");
                        stream_name.push_str(&String::from_utf8(show.to_vec()).expect("compiler emitted invalid UTF-8 for Stream name"));

                        // huh, why did you terminate with weird zero-padding :/
                        let last_non_zero = backed_up as usize + terminated - 1;
                        // println!("    actual end: {last_non_zero:08X}");
                        let next = if stream_name.len() % 4 == 0 {
                            // println!("    Four: !!positive");
                            last_non_zero + 5
                        } else {
                            // println!("    Four: negative");
                            // i.e. last_non_zero is 21, 25 - 1 = 24.
                            last_non_zero + 4 - (last_non_zero % 4)
                        };

                        reader.seek(SeekFrom::Start(next as u64)).expect("failed to handle 4-multiple");
                        // println!("    seeked to {next:08X}");

                        break 'find_stream_name stream_name;
                    } else {
                        if actual_read_size != 32 {
                            panic!("unexpected EOF: Stream name is not terminated!")
                        }

                        stream_name.push_str(&String::from_utf8(temporal_buffer.to_vec()).expect("compiler emitted invalid UTF-8 for Stream name"));
                    }
                };

                println!("    stream name: {name}");

                let header = StreamHeader {
                    offset_and_size: stream_size,
                    name,
                };

                stream_header.push(header);
            }
            println!("decodeing `#~`");

            {
                const TABLE_HEADER_SIZE: usize = size_of::<SharpTilde>();

                let mut buf = [0; TABLE_HEADER_SIZE];

                reader.read_exact(&mut buf).expect("too short input for CLR table header");

                let st: SharpTilde = unsafe { transmute(buf) };

                println!("    header was decoded: {st:?}");

                let ctb = st.contained_table_bitmask;

                let mut ask_row = |p: PredefinedRowCollection| {
                    ((ctb & (1 << p.table_id())) != 0).then(|| {
                        let mut buf = [0u8; 4];

                        reader.read_exact(&mut buf).expect("fail");

                        u32::from_le_bytes(buf)
                    }).and_then(NonZeroU32::new)
                };
                let partial_col = PartialRowCountCollection {
                    module: ask_row(PredefinedRowCollection::Module),
                    type_ref: ask_row(PredefinedRowCollection::TypeRef),
                    type_def: ask_row(PredefinedRowCollection::TypeDef),
                    field_ptr: ask_row(PredefinedRowCollection::FieldPtr),
                    field: ask_row(PredefinedRowCollection::Field),
                    method_ptr: ask_row(PredefinedRowCollection::MethodPtr),
                    method_def: ask_row(PredefinedRowCollection::MethodDef),
                    param_ptr: ask_row(PredefinedRowCollection::ParamPtr),
                    param: ask_row(PredefinedRowCollection::Param),
                    interface_impl: ask_row(PredefinedRowCollection::InterfaceImpl),
                    member_ref: ask_row(PredefinedRowCollection::MemberRef),
                    constant: ask_row(PredefinedRowCollection::Constant),
                    custom_attribute: ask_row(PredefinedRowCollection::CustomAttribute),
                    field_marshal: ask_row(PredefinedRowCollection::FieldMarshal),
                    decl_security: ask_row(PredefinedRowCollection::DeclSecurity),
                    class_layout: ask_row(PredefinedRowCollection::ClassLayout),
                    field_layout: ask_row(PredefinedRowCollection::FieldLayout),
                    standalone_sig: ask_row(PredefinedRowCollection::StandAloneSig),
                    event_map: ask_row(PredefinedRowCollection::EventMap),
                    event_ptr: ask_row(PredefinedRowCollection::EventPtr),
                    event: ask_row(PredefinedRowCollection::Event),
                    property_map: ask_row(PredefinedRowCollection::PropertyMap),
                    property_ptr: ask_row(PredefinedRowCollection::PropertyPtr),
                    property: ask_row(PredefinedRowCollection::Property),
                    method_semantics: ask_row(PredefinedRowCollection::MethodSemantics),
                    method_impl: ask_row(PredefinedRowCollection::MethodImpl),
                    module_ref: ask_row(PredefinedRowCollection::ModuleRef),
                    type_spec: ask_row(PredefinedRowCollection::TypeSpec),
                    impl_map: ask_row(PredefinedRowCollection::ImplMap),
                    field_rva: ask_row(PredefinedRowCollection::FieldRVA),
                    enc_log: ask_row(PredefinedRowCollection::EncLog),
                    enc_ptr: ask_row(PredefinedRowCollection::EncPtr),
                    assembly: ask_row(PredefinedRowCollection::Assembly),
                    assembly_processor: ask_row(PredefinedRowCollection::AssemblyProcessor),
                    assembly_os: ask_row(PredefinedRowCollection::AssemblyOS),
                    assembly_ref: ask_row(PredefinedRowCollection::AssemblyRef),
                    assembly_ref_processor: ask_row(PredefinedRowCollection::AssemblyRefProcessor),
                    assembly_ref_os: ask_row(PredefinedRowCollection::AssemblyRefOs),
                    file: ask_row(PredefinedRowCollection::File),
                    exported_type: ask_row(PredefinedRowCollection::ExportedType),
                    manifest_resource: ask_row(PredefinedRowCollection::ManifestResource),
                    nested_class: ask_row(PredefinedRowCollection::NestedClass),
                    generic_param: ask_row(PredefinedRowCollection::GenericParam),
                    method_spec: ask_row(PredefinedRowCollection::MethodSpec),
                    generic_param_constraint: ask_row(PredefinedRowCollection::GenericParamConstraint),
                };

                println!("    partial column was decoded: {partial_col:#08X?}");

                let large_string_heap = st.far_heap_string_address();
                let large_guid_heap = st.far_heap_guid_address();
                let large_blob_heap = st.far_heap_blob_address();

                println!("    large: S = {large_string_heap}, G = {large_guid_heap}, B = {large_blob_heap}");
                let modules: Option<Vec<Module>> = partial_col.module.map(|x| {
                    let vec = Vec::with_capacity(x.get() as usize);

                    for _ in 0..x.get() {

                    }
                    vec
                });

                println!("modules: {modules:?}");
                // TODO: decode continuous tables
            }

            // now we can read Tables header

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