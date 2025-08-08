mod gen;
pub use gen::*;

use crate::mutation::do_update_sizes;
use crate::rng::Prng;
use crate::grammar::resources;
use crate::grammar::types;

use super::types::Dir;

// Instances of system calls are represented as follows
#[derive(Clone, Debug)]
pub struct Syscall {
    pub def: &'static SyscallDef,
    pub args: Vec<TypeVal>,
    pub requires: Vec<resources::ResourceDesc>,
}

fn resource_ids(rsrc: &resources::ResourceDesc, rsrc_ids: &mut Vec<usize>) {
    for resource in rsrc.kind {
        rsrc_ids.push(resource.id);
        resource_ids(resource, rsrc_ids);
    }
}

impl Syscall {
    /// Create a random system call with random arguments
    pub fn new(
        prng: &mut Prng,
        resources: Vec<resources::ResourceDesc>
    ) -> Option<Self> {
        // retry a few times to get a syscall that is satisfied by our
        // available resources
        for _ in 0..100 {
            let idx = prng.get_u32() as usize % SYSCALL_TABLE.len();
            let def = &SYSCALL_TABLE[idx];
            let new = Self::new_from_def(prng, def, resources.clone());
            // dbg!(&new);
            if new.is_some() {
                return new;
            }
        }
        None
    }

    /// Create a system call according to a definition with random arguments
    pub fn new_from_def(
        prng: &mut Prng,
        def: &'static SyscallDef,
        _avail_resources: Vec<resources::ResourceDesc>
    ) -> Option<Self> {

        let mut args = vec![];
        let mut requires = vec![];

        for (_, arg) in def.args {
            args.push(gen_argument(prng, arg, &mut requires, Dir::DirIn, 0));
        }

        do_update_sizes(prng, &mut args, None);

        //if requires.is_empty() {
        //    return Some(Syscall { def, args, requires });
        //}

        //let mut available_ids: Vec<usize> = vec![];
        //for rsrc in avail_resources {
        //    available_ids.push(rsrc.id);
        //    resource_ids(&rsrc, &mut available_ids);
        //}

        //None
        Some(Syscall { def, args, requires })
    }
}

pub fn gen_const(typ: &types::Const, dir: Dir) -> TypeVal {
    TypeVal::Const(typ.clone(), dir, typ.val)
}

pub fn gen_len(typ: &types::Len, dir: Dir) -> TypeVal {
    TypeVal::Len(typ.clone(), dir, 0x10) // TODO
}

pub fn gen_resource(typ: &types::Resource, dir: Dir) -> TypeVal {
    TypeVal::Resource(typ.clone(), dir, 4)
}

pub fn gen_int(prng: &mut Prng, typ: &types::Int, dir: Dir) -> TypeVal {
    TypeVal::Int(typ.clone(), dir, prng.get_u32() as u64)
}

pub fn gen_argument(
    prng: &mut Prng,
    arg: &types::Type,
    resources: &mut Vec<resources::ResourceDesc>,
    dir: Dir,
    depth: usize
) -> TypeVal {
    if depth >= 28 {
        return TypeVal::Const(
            types::Const{
                name:"max_recursion",
                size: 8,
                val: 0,
                align: 8,
                is_varlen: false,
                bitfield_len: 0,
                bitfield_off: 0,
                arg_format: types::BinaryFormat::FormatNative,
                is_pad: false,
            },
            dir,
            0
        )
    }
    match arg {
        types::Type::Flags(typ) => {
            let idx = prng.get_u64() as usize % typ.vals.len();
            TypeVal::Flags(typ.clone(), dir, typ.vals[idx])
        },
        types::Type::Int(typ) => {
            gen_int(prng, typ, dir)
        },
        types::Type::Buffer(typ) => {
            if !typ.values.is_empty() {
                let idx = prng.get_u64() as usize % typ.values.len();
                let mut val = typ.values[idx].as_bytes().to_vec();
                if !typ.noz {
                    val.push(b'\0');
                }
                return TypeVal::Buffer(typ.clone(), dir, typ.values[idx].as_bytes().to_vec())
            }
            match typ.kind {
                types::BufferKind::BufferBlobRand => {
                    if typ.is_varlen {
                        return TypeVal::Buffer(typ.clone(), dir, vec![0;prng.get_u8() as usize])
                    } else {
                        return TypeVal::Buffer(typ.clone(), dir, vec![0;typ.size])
                    }
                },
                types::BufferKind::BufferBlobRange => {

                },
                types::BufferKind::BufferString => {
                    return TypeVal::Buffer(typ.clone(), dir, vec![])
                },
                types::BufferKind::BufferFilename => {
                    return TypeVal::Buffer(typ.clone(), dir, b"./lark\0".to_vec())
                },
                types::BufferKind::BufferText => {

                },
                types::BufferKind::BufferGlob => {

                },
                types::BufferKind::BufferCompressed => {

                },
            }
            let buf = vec![];
            TypeVal::Buffer(typ.clone(), dir, buf)
        },
        types::Type::Ptr(typ) => {
            let arg = gen_argument(
                prng,
                typ.elem,
                resources,
                typ.dir,
                depth+1
            );
            TypeVal::Ptr(typ.clone(), dir, vec![arg])
        },
        types::Type::Len(typ) => { gen_len(typ, dir) },
        types::Type::Const(typ) => { gen_const(typ, dir) },
        types::Type::Resource(typ) => {
            resources.push(typ.desc.clone());
            gen_resource(typ, dir)
        },
        types::Type::Struct(typ) => {
            let mut args = vec![];
            for field in typ.fields {
                let field_type = match &field.typ {
                    types::FieldType::Type(typ) => typ,
                    types::FieldType::Index(idx) => &types::gen::TYPE_TABLE[*idx],
                };
                let new_arg = gen_argument(
                    prng, field_type,
                    resources,
                    field.dir,
                    depth+1
                );
                args.push(new_arg);
            }
            TypeVal::Struct(typ.clone(), dir, args)
        },
        types::Type::Union(typ) => {
            let idx = prng.get_u64() as usize % typ.fields.len();
            let field = &typ.fields[idx];
            let field_type = match &field.typ {
                types::FieldType::Type(typ) => typ,
                types::FieldType::Index(idx) => &types::gen::TYPE_TABLE[*idx],
            };
            let field = vec![gen_argument(
                prng, field_type,
                resources,
                field.dir,
                depth+1
            )];
            TypeVal::Union(typ.clone(), dir, (idx, field))
        },
        types::Type::Array(typ) => {
            let mut elements = vec![];
            //let elem = typ.elem;
            for _ in 0..4 {
                let new_arg = gen_argument(
                    prng, &typ.elem,
                    resources,
                    dir,
                    depth+1
                );
                elements.push(new_arg);
            }
            TypeVal::Array(typ.clone(), dir, elements)

        },
        _ => {
            TypeVal::Const(
                types::Const{
                    name:"unimplemented",
                    size: 8,
                    val: 0,
                    align: 8,
                    is_varlen: false,
                    bitfield_len: 0,
                    bitfield_off: 0,
                    arg_format: types::BinaryFormat::FormatNative,
                    is_pad: false,
                },
                dir,
                0
            )
        }
    }
}

#[derive(Clone, Debug)]
pub enum TypeVal {
    Resource(types::Resource, Dir, u64),
    Const(types::Const, Dir, u64),
    Int(types::Int, Dir, u64),
    Flags(types::Flags, Dir, u64),
    Len(types::Len, Dir, u64),
    // Proc(Proc),
    // Vma(Vma),
    Buffer(types::Buffer, Dir, Vec<u8>),
    Array(types::Array, Dir, Vec<TypeVal>),
    Ptr(types::Ptr, Dir, Vec<TypeVal>),
    Struct(types::Struct, Dir, Vec<TypeVal>),
    Union(types::Union, Dir, (usize, Vec<TypeVal>)),
}

impl TypeVal {
    pub fn name(&self) -> &'static str {
        match self {
            TypeVal::Resource(t, ..) => { t.name },
            TypeVal::Const(t, ..) => { t.name },
            TypeVal::Int(t, ..) => { t.name },
            TypeVal::Flags(t, ..) => { t.name },
            TypeVal::Len(t, ..) => { t.name },
            TypeVal::Buffer(t, ..) => { t.name },
            TypeVal::Array(t, ..) => { t.name },
            TypeVal::Ptr(t, ..) => { t.name },
            TypeVal::Struct(t, ..) => { t.name },
            TypeVal::Union(t, ..) => { t.name },
            //TypeVal::Vma(_t) => { return "" },
            //TypeVal::Csum(_t) => { return "" },
            //TypeVal::Proc(_t) => { return "" },
        }
    }

    pub fn size(&self) -> usize {
        match self {
            TypeVal::Resource(t, ..) => { t.size },
            TypeVal::Const(t, ..) => { t.size },
            TypeVal::Int(t, ..) => { t.size },
            TypeVal::Flags(t, ..) => { t.size },
            TypeVal::Len(t, ..) => { t.size },
            TypeVal::Buffer(t, ..) => { t.size },
            TypeVal::Array(t, ..) => { t.size },
            TypeVal::Ptr(t, ..) => { t.size },
            TypeVal::Struct(t, ..) => { t.size },
            TypeVal::Union(t, ..) => { t.size },
            //TypeVal::Vma(_t) => { return 0 },
            //TypeVal::Csum(_t) => { return 0 },
            //TypeVal::Proc(_t) => { return 0 },
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallDef {
    pub id: usize,
    pub name: &'static str,
    pub args: &'static[(&'static str, types::Type)],
    pub ret: Option<types::Resource> // will always be Type::Resource
}

