use crate::grammar::syscalls::Syscall;
use crate::grammar::syscalls::TypeVal;
use crate::grammar::types;
use crate::grammar::types::IntTypeCommon;
use crate::grammar::types::BinaryFormat;
use crate::grammar::types::Resource;

#[derive(Default, Debug, Clone)]
pub struct BitVec {
    /// Internal storage for pushed bits
    bits: Vec<u8>,

    /// Track the number of bits stored
    length: usize,
}

impl BitVec {
    pub fn new() -> Self {
        BitVec::default()
    }

    fn push_bit(&mut self, bit: bool) {
        if self.length % 8 == 0 {
            self.bits.push(0);
        }
        if bit {
            let byte_pos = self.length / 8;
            let bit_pos = self.length % 8;
            self.bits[byte_pos] |= 1 << bit_pos;
        }
        self.length += 1;
    }

    fn push(&mut self, value: u64, bitsize: usize) {
        if bitsize == 0 { return; }
        //println!("Pushing: {value:#x}, bitsize: {bitsize:#x}");
        for i in 0..bitsize {
            let bit = value & (1 << i);
            self.push_bit(bit != 0);
        }
    }

    fn swap(&mut self, bytes: usize) {
        let len = self.bits.len();
        if len < bytes { return; }
        self.bits[len - bytes..len].reverse();
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bits.clone()
    }

    pub fn len(&self) -> usize {
        self.bits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}


pub struct SerializerHeap {
    /// base address to use for pointers
    pub base: u64,

    /// number of bits already used
    pub in_use: usize,
}
impl SerializerHeap {
    pub fn alloc(&mut self, src: &mut BitVec, dest: &mut BitVec) -> u64 {
        let alloc_addr = self.base + self.in_use as u64;
        self.in_use += src.bits.len();
        dest.bits.append(&mut src.bits.clone());
        alloc_addr
    }

    pub fn alloc_bytes(&mut self, src: &Vec<u8>, dest: &mut BitVec) -> u64 {
        let alloc_addr = self.base + self.in_use as u64;
        self.in_use += src.len() * 8;
        for byte in src {
            dest.push(*byte as u64, 8);
        }
        alloc_addr
    }
}

/// Denotes the location and identifier of a produced resource
#[derive(Debug)]
pub enum ResourceOutput {
    /// syscall return value
    RetVal(Resource),

    /// offset, bytesize
    MemoryOffset(Resource, usize, usize),
}

#[derive(Debug)]
pub enum CallResult {
    Integer(u64),
    Pointer(u64, Vec<u8>)
}

pub fn serialize_call(
    syscall: &Syscall,
    base: u64,
    avail_rsrcs: &[(ResourceOutput, u64)]
) -> (Vec<ResourceOutput>, [CallResult; 6]) {
    let mut serializer = SerializerHeap { base, in_use: 0, };

    let mut results: [CallResult; 6] = [
        CallResult::Integer(0), // rdi
        CallResult::Integer(0), // rsi
        CallResult::Integer(0), // rdx
        CallResult::Integer(0), // r10
        CallResult::Integer(0), // r8
        CallResult::Integer(0), // r9
    ];

    let mut resources_created: Vec<ResourceOutput> = vec![];

    if let Some(ret) = &syscall.def.ret {
        resources_created.push(
            ResourceOutput::RetVal(ret.clone())
        );
    }

    for (idx, arg) in syscall.args.iter().enumerate() {
        if idx > 5 {
            panic!("syscall had more than 6 args?");
        }
        let mut bitvec = BitVec::new();
        let v = allocate_arg_value(
            arg,
            &mut serializer,
            &mut bitvec,
            avail_rsrcs
        );
        let val = match arg {
            TypeVal::Ptr(..) => CallResult::Pointer(v, bitvec.to_bytes()),
            _ => CallResult::Integer(v)
        };
        results[idx] = val;
    }

    (resources_created, results)
}

pub fn handle_value(
    typ: &TypeVal,
    heap: &mut SerializerHeap,
    bv: &mut BitVec
) -> u64 {
    match typ {
        TypeVal::Flags(..) => {
            let mut nested_bv = BitVec::new();
            allocate_data_value(typ, heap, bv);
            heap.alloc(&mut nested_bv, bv)
        }
        TypeVal::Const(..) => {
            let mut nested_bv = BitVec::new();
            allocate_data_value(typ, heap, bv);
            heap.alloc(&mut nested_bv, bv)
        }
        TypeVal::Int(..) => {
            let mut nested_bv = BitVec::new();
            allocate_data_value(typ, heap, bv);
            heap.alloc(&mut nested_bv, bv)
        },
        TypeVal::Ptr(_, _, _ptr) => {
            // handle nested pointer, allocate then write the pointer to memory
            let mut nested_bv = BitVec::new();
            let nested = handle_ptr_value(typ, heap, &mut nested_bv);
            heap.alloc_bytes(&nested.to_le_bytes().to_vec(), bv)
        },
        TypeVal::Union(_, _, (_, var)) => {
            // handle nested pointer, allocate then write the pointer to memory
            let mut nested_bv = BitVec::new();
            allocate_data_value(&var[0], heap, &mut nested_bv);
            heap.alloc(&mut nested_bv, bv)
        },
        TypeVal::Struct(_, _, struc) => {
            let mut nested_bv = BitVec::new();
            for field in struc {
                //println!("field: {}", field.name());
                allocate_data_value(
                    field,
                    heap,
                    &mut nested_bv
                );
                //println!("nested: {:?}", &nested_bv);
            }
            heap.alloc(&mut nested_bv, bv)
        },
        TypeVal::Array(_, _, elems) => {
            let mut nested_bv = BitVec::new();
            for elem in elems {
                allocate_data_value(
                    elem,
                    heap,
                    &mut nested_bv
                );
            }
            heap.alloc(&mut nested_bv, bv)
        },
        TypeVal::Buffer(_, _, buf) => {
            heap.alloc_bytes(buf, bv)
        },
        _ => 0,
    }
}

fn handle_ptr_value(
    ptr: &TypeVal,
    heap: &mut SerializerHeap,
    bv: &mut BitVec
) -> u64 {
    //println!("ptr: {}", ptr.name());
    if let TypeVal::Ptr(_, _, inner) = ptr {
        handle_value(&inner[0], heap, bv)
    } else {
        println!("WHAT");
        0
    }
}

fn allocate_common_int<T>(bv: &mut BitVec, t: &T, v: &u64) -> (usize, usize)
where
    T: IntTypeCommon + std::fmt::Debug,
{
    //println!("\tint value: {:#x}, size: {:#x}", v, t.size());
    match t.arg_format() {
        &BinaryFormat::FormatNative => {
            if t.bitfield_len() != 0 {
                bv.push(*v, t.bitfield_len() as usize);
                if t.size() != 0 {
                    (t.bitfield_padding(), 0)
                } else {
                    (0, 0)
                }
            } else if t.is_pad() {
                let mut rem_bitsize = t.bitsize();
                while rem_bitsize > 8 {
                    rem_bitsize -= 8;
                    bv.push(0, 8);
                }
                bv.push(0, rem_bitsize as usize);
                (0, 0)

            } else {
                bv.push(*v, t.bitsize() as usize);
                (0, 0)
            }
        },
        &BinaryFormat::FormatBigEndian => {
            if t.bitfield_len() != 0 {
                bv.push(*v, t.bitfield_len() as usize);
                if t.size() != 0 {
                    //println!("{:?}", t);
                    if t.is_pad() {
                        unreachable!();
                    } else {
                        (t.bitfield_padding(), t.size() as usize)
                    }
                } else {
                    (0, t.size() as usize)
                }
            } else {
                bv.push(*v, t.size() as usize * 8);
                (0, t.size() as usize)
            }
        },
        // I don't know how these work lmao
        BinaryFormat::FormatStrDec => {
            let data = format!("{:020}", v);
            for byte in data.bytes() {
                bv.push(byte as u64, 8);
            }
            (0, 0)
        },
        BinaryFormat::FormatStrHex => {
            let data = format!("0x{:016x}", v);
            for byte in data.bytes() {
                bv.push(byte as u64, 8);
            }
            (0, 0)
        },
        BinaryFormat::FormatStrOct => {
            let data = format!("{:023o}", v);
            for byte in data.bytes() {
                bv.push(byte as u64, 8);
            }
            (0, 0)
        }
    }
}

/// Pushes data into bv according to value
fn allocate_data_value(
    value: &TypeVal,
    heap: &mut SerializerHeap,
    bv: &mut BitVec
) {
    //println!("alloc_data_value: {}", value.name());
    let (pad, flip_endian): (usize, usize) = match value {
        TypeVal::Flags(t, _, v) => {
            allocate_common_int(bv, t, v)
        },
        TypeVal::Const(t, _, v) => {
            allocate_common_int(bv, t, v)
        },
        TypeVal::Len(t, _, v) => {
            allocate_common_int(bv, t, v)
        },
        TypeVal::Int(t, _, v) => {
            allocate_common_int(bv, t, v)
        },
        TypeVal::Resource(t, _, v) => {
            //println!("RESOURCE");
            allocate_common_int(bv, t, v)
        },
        TypeVal::Buffer(_, _, data) => {
            for byte in data {
                bv.push(*byte as u64, 8);
            }
            (0, 0)
        },
        TypeVal::Ptr(..) => {
            handle_ptr_value(value, heap, bv).to_le_bytes().to_vec();
            (0, 0)
        },
        TypeVal::Union(_, _, (_, v)) => {
            allocate_data_value(&v[0], heap, bv);
            (0, 0)
        },
        TypeVal::Array(_, _, v) => {
            for elem in v {
                allocate_data_value(
                    elem,
                    heap,
                    bv
                )
            }
            (0, 0)
        },
        TypeVal::Struct(_, _, struc) => {
            for field in struc {
                //let rem = bv.length % 8;
                //let bytes = bv.length / 8;
                //println!("len: {:#x}:{:x}, field: {}", bytes, rem, field.name());
                allocate_data_value(field, heap, bv)
            }
            (0, 0)
        }
    };
    //println!("padding by: {}", pad);
    bv.push(0, pad);
    if flip_endian > 0 {
        bv.swap(flip_endian);
    }
}

fn allocate_arg_value(
    value: &TypeVal,
    heap: &mut SerializerHeap,
    bv: &mut BitVec,
    avail_rsrcs: &[(ResourceOutput, u64)]
) -> u64 {
    match value {
        TypeVal::Flags(_, _, v)  |
        TypeVal::Const(_, _, v)  |
        TypeVal::Int(_, _, v)    |
        TypeVal::Len(_, _, v) => {
            *v
        },
        TypeVal::Resource(t, _, _) => {
            for (avail, val) in avail_rsrcs {
                let avail_rsrc = match avail {
                    ResourceOutput::RetVal(r) => { r },
                    ResourceOutput::MemoryOffset(r, ..) => { r }
                };
                if avail_rsrc.desc.id == t.desc.id {
                    return *val;
                }
                for avail_kind in avail_rsrc.desc.kind {
                    for typ_kind in t.desc.kind {
                        if avail_kind.id == typ_kind.id {
                            //dbg!(avail_rsrc.name, t.name);
                            //println!("MATCHED");
                            return *val;
                        }
                    }
                }
            }
            u64::MAX
        },
        TypeVal::Buffer(_, _, data) => {
            heap.alloc_bytes(data, bv)
        },
        TypeVal::Ptr(..) => handle_ptr_value(value, heap, bv),
        _ =>  {
            // arguments should never be of type struct, union, array
            unreachable!("{:?}", value);
        }
    }
}
