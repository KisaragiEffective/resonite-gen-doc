use std::num::NonZeroU32;
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
pub struct SharpTilde {
    __reserved: u32,
    major: u8,
    minor: u8,
    // TODO: bit vector, and implies larger offsets; currently not supported
    pub heap_offset_sizes: u8,
    __reserved_2: u8,
    pub contained_table_bitmask: u64,
    mask_sorted: u64,
    // depending on contained_table_bitmask, some tables would be missing.
    // rows: PartialRowCountCollection,
}

impl SharpTilde {
    pub fn far_heap_string_address(&self) -> bool {
        (self.heap_offset_sizes & 0x01) == 0x01
    }

    pub fn far_heap_guid_address(&self) -> bool {
        (self.heap_offset_sizes & 0x02) == 0x02
    }

    pub fn far_heap_blob_address(&self) -> bool {
        (self.heap_offset_sizes & 0x04) == 0x04
    }
}

#[repr(u8)]
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[non_exhaustive]
pub enum PredefinedRowCollection {
    Module = 0,
    TypeRef,
    TypeDef,
    FieldPtr,
    Field,
    MethodPtr,
    MethodDef,
    ParamPtr,
    Param,
    InterfaceImpl,
    MemberRef,
    Constant,
    CustomAttribute,
    FieldMarshal,
    DeclSecurity,
    ClassLayout,
    FieldLayout,
    StandAloneSig,
    EventMap,
    EventPtr,
    Event,
    PropertyMap,
    PropertyPtr,
    Property,
    MethodSemantics,
    MethodImpl,
    ModuleRef,
    TypeSpec,
    ImplMap,
    FieldRVA,
    EncLog,
    EncPtr,
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
    MethodSpec,
    GenericParamConstraint,
}

impl PredefinedRowCollection {
    pub fn table_id(self) -> u32 {
        // implicit discriminants
        self as u32
    }

    pub fn rid_bit_mask(self) -> NonZeroU32 {
        todo!()
    }
}

#[derive(Debug)]
pub struct PartialRowCountCollection {
    /// 0
    pub(crate) module: Option<NonZeroU32>,
    /// 1
    pub(crate) type_ref: Option<NonZeroU32>,
    /// 2
    pub(crate) type_def: Option<NonZeroU32>,
    /// 3
    pub(crate) field_ptr: Option<NonZeroU32>,
    /// 4
    pub(crate) field: Option<NonZeroU32>,
    /// 5
    pub(crate) method_ptr: Option<NonZeroU32>,
    /// 6
    pub(crate) method_def: Option<NonZeroU32>,
    /// 7
    pub(crate) param_ptr: Option<NonZeroU32>,
    /// 8
    pub(crate) param: Option<NonZeroU32>,
    /// 9
    pub(crate) interface_impl: Option<NonZeroU32>,
    /// 10
    pub(crate) member_ref: Option<NonZeroU32>,
    /// 11
    pub(crate) constant: Option<NonZeroU32>,
    /// 12
    pub(crate) custom_attribute: Option<NonZeroU32>,
    /// 13
    pub(crate) field_marshal: Option<NonZeroU32>,
    /// 14
    pub(crate) decl_security: Option<NonZeroU32>,
    /// 15
    pub(crate) class_layout: Option<NonZeroU32>,
    /// 16
    pub(crate) field_layout: Option<NonZeroU32>,
    /// 17
    pub(crate) standalone_sig: Option<NonZeroU32>,
    /// 18
    pub(crate) event_map: Option<NonZeroU32>,
    /// 19
    pub(crate) event_ptr: Option<NonZeroU32>,
    /// 20
    pub(crate) event: Option<NonZeroU32>,
    /// 21
    pub(crate) property_map: Option<NonZeroU32>,
    /// 22
    pub(crate) property_ptr: Option<NonZeroU32>,
    /// 23
    pub(crate) property: Option<NonZeroU32>,
    /// 24
    pub(crate) method_semantics: Option<NonZeroU32>,
    /// 25
    pub(crate) method_impl: Option<NonZeroU32>,
    /// 26
    pub(crate) module_ref: Option<NonZeroU32>,
    /// 27
    pub(crate) type_spec: Option<NonZeroU32>,
    /// 28
    pub(crate) impl_map: Option<NonZeroU32>,
    /// 29
    pub(crate) field_rva: Option<NonZeroU32>,
    /// 30
    pub(crate) enc_log: Option<NonZeroU32>,
    /// 31
    pub(crate) enc_ptr: Option<NonZeroU32>,
    /// 32
    pub(crate) assembly: Option<NonZeroU32>,
    /// 33
    pub(crate) assembly_processor: Option<NonZeroU32>,
    /// 34
    pub(crate) assembly_os: Option<NonZeroU32>,
    /// 35
    pub(crate) assembly_ref: Option<NonZeroU32>,
    /// 36
    pub(crate) assembly_ref_processor: Option<NonZeroU32>,
    /// 37
    pub(crate) assembly_ref_os: Option<NonZeroU32>,
    /// 38
    pub(crate) file: Option<NonZeroU32>,
    /// 39
    pub(crate) exported_type: Option<NonZeroU32>,
    /// 40
    pub(crate) manifest_resource: Option<NonZeroU32>,
    /// 41
    pub(crate) nested_class: Option<NonZeroU32>,
    /// 42
    pub(crate) generic_param: Option<NonZeroU32>,
    /// 43
    pub(crate) method_spec: Option<NonZeroU32>,
    /// 44
    pub(crate) generic_param_constraint: Option<NonZeroU32>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum StringHeapPointer {
    Normal(u16),
    Large(u32),
}

impl StringHeapPointer {
    fn lsb(self) -> u16 {
        match self {
            StringHeapPointer::Normal(v) => v,
            StringHeapPointer::Large(m) => (m & 0x0000FFFF) as u16
        }
    }
}

#[derive(Debug)]
pub struct Module(TypeRef);

#[derive(Debug)]
pub struct TypeRef {
    flags: u32,
    name: StringHeapPointer,
    namespace: StringHeapPointer,
    extends: TypeDefOrRef,

}

#[derive(Copy, Clone, Eq, PartialEq)]
#[derive(Debug)]
pub struct ShallowRID<const TAGGING_LSB_BITS: usize> {
    repr: StringHeapPointer,
}

impl<const N: usize> ShallowRID<N> {
    fn tag(self) -> u16 {
        self.repr.lsb() & ((1 << N) - 1)
    }

    fn rid(self) -> StringHeapPointer {
        match self.repr {
            StringHeapPointer::Normal(v) => StringHeapPointer::Normal(v & !((1 << N) - 1)),
            StringHeapPointer::Large(v) => StringHeapPointer::Large(v & !((1 << N) - 1)),
        }
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct TypeDefOrRef {
    repr: ShallowRID<2>,
}

impl TypeDefOrRef {
    fn table(self) -> PredefinedRowCollection {
        match self.repr.tag() {
            0 => PredefinedRowCollection::TypeDef,
            1 => PredefinedRowCollection::TypeRef,
            2 => PredefinedRowCollection::TypeSpec,
            _ => unreachable!()
        }
    }

    fn rid(self) -> StringHeapPointer {
        self.repr.rid()
    }
}
