use crate::grammar::syscalls::Syscall;
use crate::grammar::syscalls::TypeVal;
use crate::grammar::types::BinaryFormat;
use crate::grammar::types::IntTypeCommon;

#[derive(Debug, Clone)]
pub struct BitVec {
    bits: Vec<u8>,

    // Track the number of bits stored
    length: usize,
}

impl BitVec {
    pub fn new() -> Self {
        BitVec {
            bits: Vec::new(),
            length: 0,
        }
    }

    fn push_bit(&mut self, bit: bool) {
        if self.length % 8 == 0 {
            self.bits.push(0);
        }
        if bit {
            let byte_pos = self.length / 8;
            let bit_pos = self.length % 8;
            //println!("setting bit: {byte_pos:#x}:{bit_pos:#x}");
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
        //println!("After: {:?}", self.bits);
    }

    fn swap(&mut self, bytes: usize) {
        let len = self.bits.len();
        if len < bytes { return; }
        //println!("before: {:?}", self.bits);
        self.bits[len - bytes..len].reverse();
        //println!("after: {:?}", self.bits);
    }

    fn to_bytes(&self) -> Vec<u8> {
        //println!("to_bytes: {:?}", self.bits);
        self.bits.clone()
    }

    pub fn len(&self) -> usize {
        return self.bits.len();
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

#[derive(Debug)]
pub enum CallResult {
    Integer(u64),
    Pointer(u64, Vec<u8>)
}

pub fn serialize_call(syscall: &Syscall, base: u64) -> [CallResult; 6] {
    let mut serializer = SerializerHeap { base, in_use: 0, };

    let mut results: [CallResult; 6] = [
        CallResult::Integer(0), // rdi
        CallResult::Integer(0), // rsi
        CallResult::Integer(0), // rdx
        CallResult::Integer(0), // r10
        CallResult::Integer(0), // r8
        CallResult::Integer(0), // r9
    ];

    for (idx, arg) in syscall.args.iter().enumerate() {
        if idx > 5 {
            panic!("syscall had more than 6 args?");
        }
        let mut bitvec = BitVec::new();
        let v = allocate_arg_value(arg, &mut serializer, &mut bitvec);
        let val = match arg {
            TypeVal::Ptr(..) => CallResult::Pointer(v, bitvec.to_bytes()),
            _ => CallResult::Integer(v)
        };
        results[idx] = val;
    }

    results
}

pub fn handle_value(
    typ: &TypeVal,
    heap: &mut SerializerHeap,
    bv: &mut BitVec
) -> u64 {
    //println!("{typ:?}");
    match typ {
        TypeVal::Flags(t, _, v) => {
            let vbuf = v.to_le_bytes()[0..t.size].to_vec();
            heap.alloc_bytes(&vbuf, bv)
        }
        TypeVal::Const(t, _, v) => {
            let vbuf = v.to_le_bytes()[0..t.size].to_vec();
            heap.alloc_bytes(&vbuf, bv)
        }
        TypeVal::Int(t, _, v) => {
            let vbuf = v.to_le_bytes()[0..t.size].to_vec();
            heap.alloc_bytes(&vbuf, bv)
        },
        TypeVal::Ptr(_, _, ptr) => {
            // handle nested pointer, allocate then write the pointer to memory
            let mut nested_bv = BitVec::new();
            let nested = handle_ptr_value(&ptr[0], heap, &mut nested_bv);
            heap.alloc_bytes(&nested.to_le_bytes().to_vec(), bv)
        },
        TypeVal::Union(_, _, (_, var)) => {
            // handle nested pointer, allocate then write the pointer to memory
            let mut nested_bv = BitVec::new();
            allocate_data_value(&var[0], heap, &mut nested_bv);
            heap.alloc(&mut nested_bv, bv)
        },
        TypeVal::Struct(_def, _dir, struc) => {
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
            let tmp = heap.alloc(&mut nested_bv, bv);
            //println!("bv: {:?}", &bv);
            tmp
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
            } else {
                bv.push(*v, t.size() as usize * 8);
                (0, 0)
            }
        },
        &BinaryFormat::FormatBigEndian => {
            if t.bitfield_len() != 0 {
                bv.push(*v, t.bitfield_len() as usize);
                if t.size() != 0 {
                    //println!("{:?}", t);
                    (t.bitfield_padding(), t.size() as usize)
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
            let _data = format!("{:020}", v);
            (0, 0)
        },
        BinaryFormat::FormatStrHex => {
            let _data = format!("0x{:016x}", v);
            (0, 0)
        },
        BinaryFormat::FormatStrOct => {
            let _data = format!("{:023o}", v);
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
        TypeVal::Buffer(_, _, data) => {
            //data.clone()
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
                let rem = bv.length % 8;
                let bytes = bv.length / 8;
                //println!("len: {:#x}:{:x}, field: {}", bytes, rem, field.name());
                allocate_data_value(field, heap, bv)
            }
            (0, 0)
        }
        _ => { (0, 0) },
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
    bv: &mut BitVec
) -> u64 {
    match value {
        TypeVal::Flags(_, _, v)  |
        TypeVal::Const(_, _, v)  |
        TypeVal::Int(_, _, v)    |
        TypeVal::Len(_, _, v) => {
            *v
        },
        TypeVal::Resource(..) => {
            0
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
