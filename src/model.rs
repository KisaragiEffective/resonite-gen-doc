use std::fmt::{Debug, Display, Formatter, Write};
use std::intrinsics::transmute;
use std::mem::{MaybeUninit, size_of};
use std::num::NonZeroU32;
use std::str::Utf8Error;

#[repr(C)]
#[derive(Debug)]
pub struct RawDosHeader {
    pub(crate) __magic: u16,
    cblp: u16,
    cp: u16,
    crlc: u16,
    cparhdr: u16,
    minalloc: u16,
    maxalloc: u16,
    ss: u16,
    sp: u16,
    csum: u16,
    ip: u16,
    cs: u16,
    lfarlc: u16,
    ovno: u16,
    __reserved: [u16; 4],
    oemid: u16,
    oeminfo: u16,
    __reserved_2: [u16; 10],
    pub(crate) lfanew: u32,
}

impl RawDosHeader {
    pub(crate) fn new(raw: [u8; size_of::<Self>()]) -> Self {
        Self {
            __magic: u16::from_be_bytes(raw[0..2].try_into().unwrap()),
            cblp: u16::from_le_bytes(raw[2..4].try_into().unwrap()),
            cp: u16::from_le_bytes(raw[4..6].try_into().unwrap()),
            crlc: u16::from_be_bytes(raw[6..8].try_into().unwrap()),
            //
            cparhdr: u16::from_le_bytes(raw[8..10].try_into().unwrap()),
            minalloc: u16::from_be_bytes(raw[10..12].try_into().unwrap()),
            maxalloc: u16::from_be_bytes(raw[12..14].try_into().unwrap()),
            ss: u16::from_le_bytes(raw[14..16].try_into().unwrap()),
            //
            sp: u16::from_le_bytes(raw[16..18].try_into().unwrap()),
            csum: u16::from_be_bytes(raw[18..20].try_into().unwrap()),
            ip: u16::from_be_bytes(raw[20..22].try_into().unwrap()),
            cs: u16::from_be_bytes(raw[22..24].try_into().unwrap()),
            //
            lfarlc: u16::from_le_bytes(raw[24..26].try_into().unwrap()),
            ovno: u16::from_be_bytes(raw[26..28].try_into().unwrap()),
            __reserved: [0; 4],
            oemid: u16::from_be_bytes(raw[36..38].try_into().unwrap()),
            oeminfo: u16::from_be_bytes(raw[38..40].try_into().unwrap()),
            __reserved_2: [0; 10],
            lfanew: u32::from_le_bytes(raw[60..64].try_into().unwrap()),
        }
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct RVA<T>(pub T);

impl<T> Display for RVA<T> where T: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct RawCoffHeader {
    pub(crate) sig: u32,
    machine: u16,
    pub(crate) number_of_sections: u16,
    baked_timestamp_of_unix_epoch_lsb: u32,
    pointer_to_symbol_table_deprecated: u32,
    number_of_symbol_table_deprecated: u32,
    size_of_optional_coff_header: u16,
    coff_characteristics: u16,
}

impl RawCoffHeader {
    pub(crate) fn new(raw: [u8; size_of::<Self>()]) -> Self {
        Self {
            sig: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
            machine: u16::from_le_bytes(raw[4..6].try_into().unwrap()),
            number_of_sections: u16::from_le_bytes(raw[6..8].try_into().unwrap()),
            baked_timestamp_of_unix_epoch_lsb: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
            pointer_to_symbol_table_deprecated: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
            number_of_symbol_table_deprecated: u32::from_le_bytes(raw[16..20].try_into().unwrap()),
            size_of_optional_coff_header: u16::from_le_bytes(raw[20..22].try_into().unwrap()),
            coff_characteristics: u16::from_le_bytes(raw[22..24].try_into().unwrap()),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct RawCoffField {
    pub magic: u16,
    pub major_linker: u8,
    pub minor_linker: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA<u32>,
    pub base_of_code: RVA<u32>,
    pub base_of_data: RVA<u32>,
}

impl RawCoffField {
    pub(crate) fn new(buf: [u8; size_of::<Self>()]) -> Self {
        Self {
            magic: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            major_linker: buf[2],
            minor_linker: buf[3],
            size_of_code: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            size_of_initialized_data: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            size_of_uninitialized_data: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            address_of_entry_point: RVA(u32::from_le_bytes(buf[16..20].try_into().unwrap())),
            base_of_code: RVA(u32::from_le_bytes(buf[20..24].try_into().unwrap())),
            base_of_data: RVA(u32::from_le_bytes(buf[24..28].try_into().unwrap())),
        }
    }

    pub(crate) fn bake(self) -> Result<StandardCoffField, ()> {
        const PE32: u16 = 0x010B;
        const PE32_PLUS: u16 = 0x020B;

        match self.magic {
            PE32 => {
                let Self { major_linker, minor_linker, size_of_code, size_of_initialized_data, size_of_uninitialized_data, address_of_entry_point, base_of_code, .. } = self;
                Ok(StandardCoffField {
                    major_linker,
                    minor_linker,
                    size_of_code,
                    size_of_initialized_data,
                    size_of_uninitialized_data,
                    address_of_entry_point: NonZeroU32::new(address_of_entry_point.0).map(RVA),
                    base_of_code,
                    base_of_data: unsafe { self.base_of_data },
                })
            }
            _ => return Err(())
        }
    }
}

#[derive(Debug)]
pub struct StandardCoffField {
    major_linker: u8,
    minor_linker: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: Option<RVA<NonZeroU32>>,
    pub(crate) base_of_code: RVA<u32>,
    base_of_data: RVA<u32>
}

impl StandardCoffField {
}
#[repr(C)]
#[derive(Debug)]
pub struct NtAdditionalRawCoffHeaderField {
    pub image_base_lsb: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_ver: u16,
    pub minor_os_ver: u16,
    pub major_image_ver: u16,
    pub minor_image_ver: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    /// It is opaque for us. You may (or may not) verify this by `CheckSumMappedFile`.
    __checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub stack_and_heap: ReservedMemoryInformation<u32>,
    pub __loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct ReservedMemoryInformation<M> {
    pub size_of_stack_reserve: M,
    pub size_of_stack_commit: M,
    pub size_of_heap_reserve: M,
    pub size_of_heap_commit: M,
}
#[repr(C)]
#[derive(Debug)]
pub struct ImageDataDirectory {
    pub relative_virtual_address: RVA<u32>,
    pub size: u32,
}

impl Display for ImageDataDirectory {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ZeroByteSequence<const N: usize>([Zero; N]);

#[repr(u8)]
#[derive(Debug)]
pub enum Zero {
    __Zero = 0
}

#[repr(C)]
#[derive(Debug)]
pub struct UsualDataDirectory {
    pub export_table: ImageDataDirectory,
    pub import_table: ImageDataDirectory,
    pub resource_table: ImageDataDirectory,
    pub exception_table: ImageDataDirectory,
    pub certificate_table: ImageDataDirectory,
    pub base_relocation_table: ImageDataDirectory,
    pub debug: ImageDataDirectory,
    pub architecture_data: ImageDataDirectory,
    pub global: RVA<u32>,
    __0: [u8; 4],// ZeroByteSequence<4>,
    pub tls: ImageDataDirectory,
    pub load_config: ImageDataDirectory,
    pub bound_import: ImageDataDirectory,
    pub import_address: ImageDataDirectory,
    pub delay_import_descriptor: ImageDataDirectory,
    pub clr_runtime_header: ImageDataDirectory,
    __0_2: [u8; 8],
}

impl UsualDataDirectory {
    pub(crate) fn bake(self) -> Result<DataDirectory, Self> {
        if self.__0.into_iter().all(|x| x == 0) && self.__0_2.into_iter().all(|x| x == 0) {
            Ok(unsafe { transmute(self) })
        } else {
            Err(self)
        }
    }
}

impl Display for UsualDataDirectory {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DataDirectory {
    /// `.edata`
    pub export_table: ImageDataDirectory,
    /// `.idata`
    pub import_table: ImageDataDirectory,
    /// `.rsrc`
    pub resource_table: ImageDataDirectory,
    /// `.pdata`
    pub exception_table: ImageDataDirectory,
    pub certificate_table: ImageDataDirectory,
    /// `.reloc`
    pub base_relocation_table: ImageDataDirectory,
    /// `.debug`
    pub debug: ImageDataDirectory,
    pub architecture_data: ImageDataDirectory,
    pub global: u32,
    __0: ZeroByteSequence<4>,
    /// `.tls`
    pub tls: ImageDataDirectory,
    pub load_config: ImageDataDirectory,
    pub bound_import: ImageDataDirectory,
    pub import_address: ImageDataDirectory,
    pub delay_import_descriptor: ImageDataDirectory,
    /// `.cormeta`
    pub clr_runtime_header: ImageDataDirectory,
    __0_2: ZeroByteSequence<8>,
}

#[derive(Debug)]
enum DataAndBase {
    PE32 {
        base_of_data: u32,
        nt_image_base: u32,
    },
    // i.e. brolib_x64
    PE32Plus {
        nt_image_base: u64,
    }
}

#[repr(transparent)]
pub struct SectionName([u8; 8]);

impl SectionName {
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        core::str::from_utf8(&self.0).map(|s| s.trim_end_matches('\0'))
    }
}

impl Debug for SectionName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Ok(s) = self.as_str() {
            f.write_str(s)
        } else {
            f.write_str(&format!(".({:?})", self.0))
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct CoffRawSectionTableEntry {
    pub name: SectionName,
    pub virtual_size: u32,
    pub virtual_address: u32,
    /// section size
    pub size_of_raw_data: u32,
    /// first address
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct ClrMetadata {

}

#[derive(Debug)]
pub struct PortableExecutableFormat {
    pub dos: RawDosHeader,
    // opaque.
    pub dos_stub: Vec<u8>,
    pub coff: StandardCoffField,
    pub nt: NtAdditionalRawCoffHeaderField,
    pub dotnet: Option<ClrMetadata>,
}
