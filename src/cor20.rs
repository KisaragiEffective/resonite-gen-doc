use crate::model::ImageDataDirectory;

#[repr(C)]
#[derive(Debug)]
pub struct Cor20Header {
    __cb: u32,
    pub(crate) major_runtime: u16,
    pub(crate) minor_runtime: u16,
    pub(crate) metadata: ImageDataDirectory,
    flags: u32,
    entry_point_token_or_rva: u32,
    resources: ImageDataDirectory,
    strong_name_signature: ImageDataDirectory,
    code_manager_table: ImageDataDirectory,
    vtable_fixups: ImageDataDirectory,
    export_address_table_jumps: ImageDataDirectory,
}

pub struct MetadataHeader {
    pub(crate) signature: u32,
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) __reserved: u32,
    pub(crate) version: String,
    pub(crate) flags: u16,
    pub(crate) number_of_streams: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct StreamSize {
    pub(crate) offset_from_metadata_header: u32,
    pub(crate) size: u32,
}

#[derive(Debug)]
pub struct StreamHeader {
    pub(crate) offset_and_size: StreamSize,
    pub(crate) name: String,
}

#[repr(C)]
#[derive(Debug)]
pub struct RawTableHeader {
    __reserved: u32,
    major: u8,
    minor: u8,
    // TODO: bit vector, and implies larger offsets; currently not supported
    heap_offset_sizes: u8,
    __reserved_2: u8,
    contained_table_bitmask: u64,
    mask_sorted: u64,
    // depending on contained_table_bitmask
    rows: PartialRowCollection,
}

#[repr(u8)]
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum PredefinedRowCollection {
    Module,
    TypeRef,
    TypeDef,
    Field,
    MethodDef,
    Param,
    InterfaceImpl,
    MemberRef,
    Constant,
    CustomAttribute,
    FieldMarshal,
    DeclSecurity,
    ClassLayout,
    fieldLayout,
    StandAloneSig,
    EventMap,
    Event,
    PropertyMap,
    Property,
    MethodSemantics,
    MethodImpl,
    ModuleRef,
    TypeSpec,
    ImplMap,
    FieldRVA,
    Assembly,
    AssemblyProcessor,
    AssemblyOS,
    AssemblyRef,
    AssemblyRefProcessor,
    AssemblyRefOs,
    File,
    ExportedType,
    ManifestResource,
    NestedClass,
    GenericParam,
    GenericParamConstraint,
}

#[derive(Debug)]
pub struct PartialRowCollection {

}