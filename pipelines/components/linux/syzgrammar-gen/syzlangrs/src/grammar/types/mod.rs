use crate::grammar::resources::ResourceDesc;
pub mod gen;
use std::cmp;

#[derive(Clone, Debug)]
pub enum BinaryFormat {
	FormatNative,
	FormatBigEndian,
	FormatStrDec,
	FormatStrHex,
	FormatStrOct
}

#[derive(Clone, Copy, Debug)]
pub enum Dir { // Direction
    DirIn,
    DirOut,
    DirInOut
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub arg_format: BinaryFormat,
    pub desc: ResourceDesc
}

#[derive(Clone, Debug)]
pub struct Const {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub arg_format: BinaryFormat,
    pub bitfield_len: u64,
    pub bitfield_off: u64,
    pub val: u64,
    pub is_pad: bool
}

#[derive(Clone, Debug)]
pub enum IntKind {
    IntPlain,
    IntRange(usize, usize) // RangeBegin, RangeEnd
}

#[derive(Clone, Debug)]
pub struct Int {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub arg_format: BinaryFormat,
    pub bitfield_len: u64,
    pub bitfield_off: u64,
    pub kind: IntKind
}

#[derive(Clone, Debug)]
pub struct Flags {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub arg_format: BinaryFormat,
    pub bitfield_len: u64,
    pub bitfield_off: u64,
    pub vals: &'static [u64]
}

#[derive(Clone, Debug)]
pub struct Len {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub arg_format: BinaryFormat,
    pub bitfield_len: u64,
    pub bitfield_off: u64,
    pub path: &'static [&'static str], // argument indexes this length is associated with
    pub offset: bool, // offset from start of parent/base obj
}

// TODO
// struct Proc {
//     name: &'static str,
// }

// TODO
// struct Vma {
//     name: &'static str,
// }

#[derive(Clone, Debug)]
pub enum BufferKind {
    BufferBlobRand,
    BufferBlobRange,
    BufferString,
    BufferFilename,
    BufferText,
    BufferGlob,
    BufferCompressed,
}

#[derive(Clone, Debug)]
pub struct Buffer {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub kind: BufferKind,
    pub is_varlen: bool,
    pub values: &'static [&'static str],
    pub range_begin: u64,
    pub range_end: u64,
    pub noz: bool // is zero-terminated
}

#[derive(Clone, Debug)]
pub enum ArrayKind {
    ArrayRandLen,
    ArrayRangeLen(usize, usize) // RangeBegin, RangeEnd
}

#[derive(Clone, Debug)]
pub struct Array {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub kind: ArrayKind,
    pub is_varlen: bool,
    pub elem: &'static Type
}

#[derive(Clone, Debug)]
pub struct Ptr {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub elem: &'static Type,
    pub dir: Dir
}

#[derive(Clone, Debug)]
pub enum FieldType {
    /// the type of this field
    Type(Type),

    /// index of the field in the types table
    Index(usize)
}

/// Describes a field of a Union or Struct
#[derive(Clone, Debug)]
pub struct Field {
    pub name: &'static str,
    pub typ: FieldType,
    pub has_dir: bool,
    pub dir: Dir
}

#[derive(Clone, Debug)]
pub struct Struct {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub fields: &'static [Field]
}

#[derive(Clone, Debug)]
pub struct Union {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub fields: &'static [Field],
    pub varlen: bool,
}

#[derive(Clone, Debug)]
pub struct Vma {
}
#[derive(Clone, Debug)]
pub struct Proc {
}
#[derive(Clone, Debug)]
pub struct Csum {
}

#[derive(Clone, Debug)]
pub enum Type {
    Resource(Resource),
    Const(Const),
    Int(Int),
    Flags(Flags),
    Len(Len),
    Buffer(Buffer),
    Array(Array),
    Ptr(Ptr),
    Struct(Struct),
    Union(Union),
    Proc(Proc),
    Vma(Vma),
    Csum(Csum),
}

pub trait BaseType {
    fn size(&self) -> usize;
    fn name(&self) -> &'static str;
}

macro_rules! impl_base_type {
    ($type:ty) => {
        impl BaseType for $type {
            fn size(&self) -> usize { self.size }
            fn name(&self) -> &'static str { self.name }
        }
    };
}

impl_base_type!(Resource);
impl_base_type!(Const);
impl_base_type!(Int);
impl_base_type!(Flags);
impl_base_type!(Len);
impl_base_type!(Buffer);
impl_base_type!(Array);
impl_base_type!(Ptr);
impl_base_type!(Struct);
impl_base_type!(Union);

//impl_base_type!(Proc);
//impl_base_type!(Vma);
//impl_base_type!(Csum);

impl BaseType for Proc {
    fn size(&self) -> usize { 0 }
    fn name(&self) -> &'static str { "" }
}

impl BaseType for Vma {
    fn size(&self) -> usize { 0 }
    fn name(&self) -> &'static str { "" }
}

impl BaseType for Csum {
    fn size(&self) -> usize { 0 }
    fn name(&self) -> &'static str { "" }
}

impl Type {
    pub fn name(&self) -> &'static str {
        match self {
            Type::Resource(t) => { t.name },
            Type::Const(t) => { t.name },
            Type::Int(t) => { t.name },
            Type::Flags(t) => { t.name },
            Type::Len(t) => { t.name },
            Type::Buffer(t) => { t.name },
            Type::Array(t) => { t.name },
            Type::Ptr(t) => { t.name },
            Type::Struct(t) => { t.name },
            Type::Union(t) => { t.name },
            Type::Vma(_t) => { "" },
            Type::Csum(_t) => { "" },
            Type::Proc(_t) => { "" },
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Type::Resource(t) => { t.size },
            Type::Const(t)    => { t.size },
            Type::Int(t)      => { t.size },
            Type::Flags(t)    => { t.size },
            Type::Len(t)      => { t.size },
            Type::Buffer(t)   => { t.size },
            Type::Array(t)    => { t.size },
            Type::Ptr(t)      => { t.size },
            Type::Struct(t)   => { t.size },
            Type::Union(t)    => { t.size },
            Type::Vma(_t)     => { 0 },
            Type::Csum(_t)    => { 0 },
            Type::Proc(_t)    => { 0 },
        }
    }
}

pub trait IntTypeCommon {
    fn size(&self) -> u64;
    fn align(&self) -> u64;
    fn arg_format(&self) -> &BinaryFormat;
    fn bitfield_len(&self) -> u64;
    fn bitfield_off(&self) -> u64;

    fn bitsize(&self) -> u64 {
        if !matches!(
            self.arg_format(),
            BinaryFormat::FormatNative |
            BinaryFormat::FormatBigEndian
        ) {
            64
        } else if self.bitfield_len() != 0 {
            self.bitfield_len()
        } else {
            self.size() * 8
        }
    }

    fn bitfield_padding(&self) -> usize {
        if self.size() == 0 {
            return 0;
        }
        // println!("size: {:x}, bitfield_off: {:x}, bitfield_len: {:x}", self.size(), self.bitfield_off(), self.bitfield_len());
        ((self.align()*8) - (self.bitfield_off() + self.bitfield_len())) as usize
    }
}

impl IntTypeCommon for Int {
    fn arg_format(&self) -> &BinaryFormat { &self.arg_format }
    fn size(&self) -> u64 { self.size as u64 }
    fn align(&self) -> u64 { self.align as u64 }
    fn bitfield_len(&self) -> u64 { self.bitfield_len }
    fn bitfield_off(&self) -> u64 { self.bitfield_off}
}

impl IntTypeCommon for Len {
    fn arg_format(&self) -> &BinaryFormat { &self.arg_format }
    fn size(&self) -> u64 { self.size as u64 }
    fn align(&self) -> u64 { self.align as u64 }
    fn bitfield_len(&self) -> u64 { self.bitfield_len }
    fn bitfield_off(&self) -> u64 { self.bitfield_off}
}

impl IntTypeCommon for Flags {
    fn arg_format(&self) -> &BinaryFormat { &self.arg_format }
    fn size(&self) -> u64 { self.size as u64 }
    fn align(&self) -> u64 { self.align as u64 }
    fn bitfield_len(&self) -> u64 { self.bitfield_len }
    fn bitfield_off(&self) -> u64 { self.bitfield_off}
}

impl IntTypeCommon for Const {
    fn arg_format(&self) -> &BinaryFormat { &self.arg_format }
    fn size(&self) -> u64 { self.size as u64 }
    fn align(&self) -> u64 { self.align as u64 }
    fn bitfield_len(&self) -> u64 { self.bitfield_len }
    fn bitfield_off(&self) -> u64 { self.bitfield_off}
}
