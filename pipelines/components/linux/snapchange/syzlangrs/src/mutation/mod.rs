use crate::grammar::syscalls::{
    gen_argument, gen_int, Syscall, TypeVal
};
use crate::grammar::types::{self, ArrayKind, BufferKind, Dir, IntTypeCommon, Type};
use crate::rng::Prng;
use crate::{Corpus, Prog};

use self::size::mutate_size;
mod size;

const MAX_BLOB_LEN: u64 = 100u64 << 10;
const MAX_CALLS: usize = 30;

// const SPECIAL_PTRS: &'static [TypeVal] = &[
//     TypeVal::Const(
//         types::Const {
//             name: "NullPtr",
//             size: 8,
//             align: 0,
//             val: 0,
//             arg_format: BinaryFormat::FormatNative,
//             bitfield_len: 0
//         },
//         Dir::DirOut,
//         0
//     ),
//     TypeVal::Const(
//         types::Const {
//             name: "NonCanonical",
//             size: 8,
//             align: 0,
//             val: 0,
//             arg_format: BinaryFormat::FormatNative,
//             bitfield_len: 0
//         },
//         Dir::DirOut,
//         0x9999999999999999
//     ),
//     TypeVal::Const(
//         types::Const {
//             name: "KernelPtr",
//             size: 8,
//             align: 0,
//             val: u64::MAX,
//             arg_format: BinaryFormat::FormatNative,
//             bitfield_len: 0
//         },
//         Dir::DirOut,
//         u64::MAX
//     ),
// ];

pub struct MutateOpts {
    pub expected_iterations: u64,
    pub mutate_arg_count: u64,

    pub squash_weight: u64,
    pub splice_weight: u64,
    pub mutate_arg_weight: u64,
    pub insert_weight: u64,
    pub remove_call_weight: u64,
}

const DEFAULT_MUTATE_OPTS: MutateOpts = MutateOpts {
    expected_iterations: 5,
    mutate_arg_count: 3,

    squash_weight: 50,
    splice_weight: 200,
    mutate_arg_weight: 100,
    insert_weight: 25,
    remove_call_weight: 10,

    //squash_weight: 0,
    //splice_weight: 0,
    //mutate_arg_weight: 100,
    //insert_weight: 0,
    //remove_call_weight: 0,
};

impl MutateOpts {
    pub fn weight(&self) -> u64 {
        self.squash_weight +
           self.splice_weight +
           self.mutate_arg_weight +
           self.insert_weight +
           self.remove_call_weight
    }
}

pub fn mutate(prng: &mut Prng, corpus: &mut Corpus, prog: &mut Prog) {
    mutate_with_opts(prng, corpus, prog, &DEFAULT_MUTATE_OPTS);
}

pub fn mutate_with_opts(
    prng: &mut Prng,
    corp: &mut Corpus,
    prog: &mut Prog,
    opts: &MutateOpts
) {
    let total_weight = opts.weight();
    // println!("{:?}", &prog);
    let mut ctx = Mutator { prng: &mut prng.clone(), _corp: corp, prog, opts };

    // println!("iters: {iters}, {}", opts.expected_iterations);
    let mut stop = false;
    while !stop {
        if ctx.prog.syscalls.is_empty() { break; }
        let mut ok = false;

        // TODO This might be wrong
        let mut mutated = false;

        let mut val = prng.int_n(total_weight);
        val -= opts.squash_weight as i64;
        if !mutated && val < 0 {
            // println!("squash_any");
            ok = ctx.squash_any();
            mutated = true;
        }
        val -= opts.splice_weight as i64;
        if !mutated && val < 0 {
            // println!("splice");
            ok = ctx.splice();
            mutated = true;
        }
        val -= opts.insert_weight as i64;
        if !mutated && val < 0 {
            // println!("ins");
            ok = ctx.insert_call();
            mutated = true;
        }
        val -= opts.mutate_arg_weight as i64;
        if !mutated && val < 0 {
            //println!("mut");
            ok = ctx.mutate_arg();
            mutated = true;
        }
        if !mutated {
            // println!("rm");
            ok = ctx.remove_call();
            mutated = true;
        }

        if !mutated { unreachable!(); }

        if ok { stop = true; }
        if stop && prng.one_of(opts.expected_iterations) {
            break
        }
    }
}

struct Mutator<'a> {
    prng: &'a mut Prng,
    _corp: &'a mut Corpus,
    prog: &'a mut Prog,
    opts: &'a MutateOpts,
}

impl Mutator<'_> {

    pub fn squash_any(&mut self) -> bool {
        false
    }

    pub fn splice(&mut self) -> bool {
        false
    }

    pub fn insert_call(&mut self) -> bool {
        let prog = &mut self.prog;
        if prog.syscalls.len() > MAX_CALLS {
            return false;
        }
        if let Some(new) = Syscall::new(self.prng, vec![]) {
            let idx: usize = self.prng.biased_rand(
                prog.syscalls.len() as u64 + 1,
                5
            ) as usize;
            prog.syscalls.insert(idx, (new, None));
        };
        true
    }

    pub fn remove_call(&mut self) -> bool {
        let prog = &mut self.prog;
        if prog.syscalls.is_empty() {
            return false;
        }
        let idx: usize = self.prng.uint_n(prog.syscalls.len() as u64) as usize;
        prog.syscalls.remove(idx);
        true
    }

    pub fn mutate_arg(&mut self) -> bool {
        let prog = &mut self.prog;
        if prog.syscalls.is_empty() {
            return false;
        }
        let idx: usize = self.prng.uint_n(prog.syscalls.len() as u64) as usize;
        //println!("idx: {idx}");
        //println!("{}", prog.syscalls[idx].0.def.name);
        let (call, _) = &mut prog.syscalls[idx];
        for _ in 0..self.prng.uint_n(self.opts.mutate_arg_count) {
            //println!("idx: {idx}");
            let mut update_sizes = true;
            if call.args.is_empty() {
                return false;
            }
            let mut call_traces = vec![];
            collect_arg_traces(&call.args, &mut call_traces, &[]);
            if call_traces.is_empty() {
                return false;
            }
            let arg_idx = self.prng.uint_n(call_traces.len() as u64) as usize;
            // println!("{:?}", call);
            // println!("{}", arg_idx);
            let res = mutate_arg_from_trace(
                self.prng,
                &mut call.args,
                &None,
                call_traces[arg_idx].as_slice(),
                &mut update_sizes
            );
            if !res {
                continue;
            }

            if update_sizes {
                do_update_sizes(self.prng, &mut call.args, None);
            }

            if res {
                break;
            }
            //println!("{:?}", call);
        }
        true
    }
}

pub fn mutate_arg(
    prng: &mut Prng,
    parent_args: &Vec<TypeVal>,
    parent_typ: &Option<Type>,
    arg: &mut TypeVal,
    update_sizes: &mut bool
) {
    // println!("mutating: {:?}", &arg);
    match arg {
        TypeVal::Resource(..) => { },
        TypeVal::Const(..) => { },
        TypeVal::Int(t, dir, v) => {
            //println!("before {}", &v);
            if prng.bin() {
                *arg = gen_int(prng, t, *dir);
                return;
            }
            if t.align == 0 {
                *v = mutate_int(prng, t, *v);
            } else {
                *v = mutate_aligned_int(prng, t, *v);
            }
            *v = truncate_to_bit_size(*v, t.bitsize());
            //println!("after {}", &v);
        },
        TypeVal::Flags(t, _, v) => {
            let oldval = *v;
            loop {
                *v = prng.flags(t.vals, t.bitfield_len > 0, *v);
                if  oldval != *v { break; }
            }
        },
        TypeVal::Len(t, _, v) => {
            //println!("mutating len! {}", &v);
            if let Some(parent_typ) = parent_typ {
                mutate_size(prng, t, parent_args, parent_typ, v, false);
                *update_sizes = false;
                //println!("mutated len! {}", &v);
            }
        },
        TypeVal::Buffer(t, dir, v) => {
            mutate_buffer(prng, t, dir, v);

        },
        TypeVal::Array(t, dir, v) => {
            //println!("mutating array! current length: {}", v.len());
            mutate_array(prng, t, dir, v);
            //println!("mutated array! current length: {}", v.len());

        },
        TypeVal::Ptr(_t, _, _v) => {
            // FIXME: I don't think this is right, sets the target
            // rather than the value
            // if prng.one_of(1000) {
            //     let index = prng.uint_n(3) as usize;
            //     *v = Box::new(SPECIAL_PTRS[index].clone());
            // }
        },
        TypeVal::Struct(_t, _, _v) => { },
        TypeVal::Union(t, dir, (idx, v)) => {
            //println!("Mutating union, pre: {}; {}", idx, v.name());
            let new = gen_argument(
                prng,
                &mut types::Type::Union(t.clone()),
                &mut vec![],
                *dir,
                0
            );
            match new {
                TypeVal::Union(_, _, (new_idx, new_v)) => {
                    *idx = new_idx;
                    *v = new_v;
                }
                _ => {
                    unreachable!();
                }
            }
            //println!("Mutating union, post: {}", idx);
        }
    }
}

pub fn regenerate(prng: &mut Prng, arg: &mut Type, dir: Dir) -> TypeVal {
    let depth = 0;
    gen_argument(prng, arg, &mut vec![], dir, depth)
}

pub fn mutate_int(prng: &mut Prng, arg: &types::Int, val: u64) -> u64 {
    if prng.one_of(3) {
        val + (prng.int_n(4)+1) as u64
    } else if prng.one_of(2) {
        val - (prng.int_n(4)+1) as u64
    } else if prng.one_of(3) {
        let width = 1 << prng.int_n(4);
        let mask = (1<<(width<<3))-1;
        val & mask as u64
    } else {
        val ^ (1 << prng.uint_n(arg.bitsize()))
    }
}

pub fn mutate_aligned_int(prng: &mut Prng, arg: &types::Int, val: u64) -> u64 {
    // println!("mutating aligned int {:?}", arg);
    let (range_begin, range_end) = {
        if let types::IntKind::IntRange(range_begin, range_end) = arg.kind {
            (range_begin, range_end)
        } else {
            (0, 0)
        }
    };
    let mut range_end = range_end;
    if range_begin == 0 && range_end as i64 == -1 {
        range_end = 1usize << (arg.bitsize()-1);
    }
    let mut index = (val-range_begin as u64) / arg.align as u64;
    let misalignment = (val-range_begin as u64) % (arg.align as u64);
    if prng.one_of(3) {
        index += prng.uint_n(4) + 1;
    } else if prng.one_of(2) {
        index = index.wrapping_sub(prng.uint_n(4) + 1);
    } else {
        index ^= 1 << prng.uint_n(arg.bitsize());
    }
    let last_index = (range_end - range_begin) / arg.align;
    index %= last_index as u64 + 1;
    (range_begin + index as usize * arg.align) as u64 + misalignment
}

pub fn mutate_buffer(
    prng: &mut Prng,
    typ: &types::Buffer,
    dir: &mut Dir,
    val: &mut Vec<u8>
) -> bool {
    let mut min_len = 0u64;
    let mut max_len = MAX_BLOB_LEN;
    if matches!(typ.kind, BufferKind::BufferBlobRange) {
        min_len = typ.range_begin;
        max_len = typ.range_end;
    }
    if matches!(dir, Dir::DirOut) {
        if matches!(typ.kind, BufferKind::BufferFilename) && prng.one_of(100) {
            val.resize(prng.rand_filename_len() as usize, 0);
        } else {
            val.resize(
                mutate_buffer_size(
                    prng,
                    val.len() as u64,
                    min_len,
                    max_len
                ) as usize,
                0
            );
        }
        return true;
    }
    // prevents an infinite loop in mutate data
    // TODO: why do we need this and syzkaller doesn't
    if max_len == 0 {
        return false
    }
    match typ.kind {
        BufferKind::BufferBlobRand | BufferKind::BufferBlobRange => {
            //println!("v: {:?}", &val);
            mutate_data(prng, val, min_len, max_len);
            //println!("v: {:?}", &val);
        },
        _ => {}
    }
    true
}

pub fn mutate_data(
    prng: &mut Prng,
    data: &mut Vec<u8>,
    min_len: u64,
    max_len: u64
) {
    let mut stop = false;
    loop {
        let ok = mutate_data_impl(prng, data, min_len, max_len);
        if ok { stop = true; }
        if stop && prng.one_of(3) {
            break;
        }
    }
}

pub fn mutate_data_impl(
    prng: &mut Prng,
    data: &mut Vec<u8>,
    min_len: u64,
    max_len: u64
) -> bool {
    let opt = prng.uint_n(7);
    // println!("mut: {} {}", opt, max_len);
    match opt {
        0 => {
            // bitflip
            if data.is_empty() {
                return false;
            }
            let byt = prng.uint_n(data.len() as u64) as usize;
            let bit = prng.uint_n(8) as u8;
            data[byt] ^= 1 << bit;
            true
        },
        1 => {
            // insert bytes
            if data.is_empty() || data.len() as u64 > max_len {
                return false;
            }
            let mut n = prng.int_n(16) + 1;
            let r = max_len as i64 - data.len() as i64;
            if  n > r {
                n = r;
            }
            let pos = prng.int_n(data.len() as u64) as usize;
            data.resize((data.len() as i64 + n) as usize, 0);
            // what does this do? copy(data[(pos+n)..], data[pos..]);
            for i in 0..data[(pos + n as usize)..].len() {
                data[pos + n as usize + i] = data[pos + i];
            }
            for i in 0..n {
                data[pos + i as usize] = prng.get_u8();
            }
            if data.len() as u64 > max_len || prng.bin() {
                data.resize(data.len() - n as usize, 0);
            }
            true
        },
        2 => {
            // remove bytes
            if data.is_empty() {
                return false;
            }
            let mut n: i64 = prng.int_n(16) + 1;
            if n > data.len() as i64 {
                n = data.len() as i64;
            }
            let mut pos = 0;
            if n < data.len() as i64 {
                pos = prng.int_n((data.len() as i64 - n) as u64);
            }
            for i in 0i64..data[(pos + n) as usize..].len() as i64 {
                data[(pos+i) as usize] = data[(pos+n+i) as usize];
            }
            data.resize(data.len() - n as usize, 0);
            if data.len() < min_len as usize || prng.bin() {
                data.resize(data.len() + n as usize, 0);
            }
            true
        },
        3 => {
            // append
            if data.len() as u64 >= max_len {
                return false;
            }
            let max = 256;
            let mut n = max - prng.biased_rand(max, 10);
            let r = max_len - data.len() as u64;
            if n > r {
                n = r
            }
            for _ in 0..n {
                data.push(prng.get_u8());
            }
            true
        },
        4 => {
            // replace
            let width = 1 << prng.int_n(4);
            if data.len() < width {
                return false;
            }
            let i = prng.int_n((data.len() - width + 1) as u64) as usize;
            store_int(data, prng.get_u64(), i, width);
            true
        },
        5 => {
            // add/subtract
            let width = 1 << prng.int_n(4);
            if data.len() < width {
                return false;
            }
            let i = prng.int_n((data.len() - width + 1) as u64) as usize;
            let mut v = load_int(data, i, width);
            let max_delta = 35;
            let mut delta = prng.uint_n(2 * max_delta + 1).wrapping_sub(max_delta);
            if delta == 0 {
                delta = 1;
            }
            if prng.one_of(10) {
                v =  swap_int(v, width);
                v = v.wrapping_add(delta);
                v = swap_int(v, width);
            } else {
                v = v.wrapping_add(delta);
            }
            store_int(data, v, i, width);
            true
        },
        6 => {
            // set to interesting values TODO this doesn't do what it says lol
            let width = (1 << prng.int_n(4)) as usize;
            if data.len() < width {
                return false;
            }
            let i = prng.int_n((data.len() - width + 1) as u64);
            let mut value = prng.get_u64();
            if prng.one_of(10) {
                value = value.swap_bytes();
            }
            store_int(data, value, i as usize, width);
            true
        },
        _ => {
            unreachable!();
        }
    }
}

pub fn mutate_array(
    prng: &mut Prng,
    typ: &mut types::Array,
    dir: &Dir,
    elems: &mut Vec<TypeVal>,
) {
    if elems.len() > 1 && prng.one_of(5) {
        while !prng.one_of(3) {
            let i = prng.uint_n(elems.len() as u64) as usize;
            let j = prng.uint_n(elems.len() as u64) as usize;
            elems.swap(i, j);
        }
    }

    let count = match typ.kind {
        ArrayKind::ArrayRandLen => {
            if prng.bin() {
                let mut count = elems.len() as u64;
                while prng.bin() {
                    count += 1;
                };
                count
            } else {
                loop {
                    //count = prng.rand_array_len();
                    let maxlen = 10;
                    let count = (maxlen - prng.biased_rand(maxlen+1, 10) + 1) % (maxlen + 1);
                    if count != elems.len() as u64 {
                        break count;
                    }
                }
            }
        },
        ArrayKind::ArrayRangeLen(begin, end) => {
            if begin == end {
                return;
            }
            loop {
                let count = begin as u64 + prng.uint_n((end-begin+1) as u64);
                if count != elems.len() as u64 {
                    break count;
                }
            }
        }
    };

    //println!("new elems: {count}");

    if count > elems.len() as u64 {
        while count > elems.len() as u64 {
            let new_elem = gen_argument(
                prng,
                typ.elem,
                &mut vec![],
                *dir,
                0,
            );
            elems.push(new_elem);
        }
    } else if count < elems.len() as u64 {
        elems.truncate(count as usize);
    }
}

pub fn mutate_buffer_size(
    prng: &mut Prng,
    curr_len: u64,
    min_len: u64,
    max_len: u64
) -> u64 {
    let mut new_size: i64 = curr_len as i64;
    while new_size == curr_len as i64 {
        new_size += prng.int_n(33) - 16;
        if new_size < min_len as i64 {
            new_size = min_len as i64;
        } else if new_size > max_len as i64 {
            new_size  = max_len as i64;
        }
    }
    new_size as u64
}

pub fn truncate_to_bit_size(v: u64, bitsize: u64) -> u64 {
    if bitsize == 64 { return v }
    v & ((1usize << bitsize)-1) as u64
}

// Syzkaller flattens the arguments into a list then chooses to mutate a random
// argument, with borrowing rules in rust that sounds like a PitA. So instead,
// collect the indicies of the types to traverse in order to reach each
// argument.
pub fn collect_arg_traces(
    args: &[TypeVal],
    traces: &mut Vec<Vec<usize>>,
    current_trace: &[usize]
) {
    for (index, arg) in args.iter().enumerate() {
        match &arg {
            &TypeVal::Const(..)     |
            &TypeVal::Int(..)       |
            &TypeVal::Flags(..)     |
            &TypeVal::Len(..)       |
            &TypeVal::Resource(..)  |
            &TypeVal::Buffer(..) => {
                let mut trace = current_trace.to_owned();
                trace.push(index);
                traces.push(trace.clone());
            },
            &TypeVal::Union(_, _, (_, v)) => {
                let mut trace = current_trace.to_owned();
                trace.push(index);
                traces.push(trace.clone());
                collect_arg_traces(v, traces, &trace);
            },
            &TypeVal::Struct(_, _, v) |
            &TypeVal::Array(_, _, v)  |
            &TypeVal::Ptr(_, _, v) => {
                let mut trace = current_trace.to_owned();
                trace.push(index);
                traces.push(trace.clone());
                collect_arg_traces(v, traces, &trace);
            }
        }
    }
}

pub fn mutate_arg_from_trace(
    prng: &mut Prng,
    args: &mut Vec<TypeVal>,
    typ: &Option<Type>,
    trace: &[usize],
    update_sizes: &mut bool
) -> bool {
    if trace.is_empty() || args.is_empty() {
        unreachable!();
    }

    let index = trace[0];
    if index >= args.len() {
        unreachable!();
    }

    if trace.len() == 1 {
        let index = trace[0];
        let args_clone = args.clone();
        mutate_arg(prng, &args_clone, typ, &mut args[index], update_sizes);
        return true;
    }

    //dbg!(&args[index]);
    //dbg!(&trace);
    match &mut args[index] {
        TypeVal::Const(..)    |
        TypeVal::Int(..)      |
        TypeVal::Flags(..)    |
        TypeVal::Len(..)      |
        TypeVal::Resource(..) |
        TypeVal::Buffer(..) => {
            // something went wrong if we reach this
            unreachable!();
        }
        TypeVal::Union(t, _, (_, v)) => {
            mutate_arg_from_trace(prng, v, &None, &trace[1..], update_sizes)
        },
        TypeVal::Ptr(t, _, v) => {
            // Continue tracing deeper into the structure.
            mutate_arg_from_trace(prng, v, &None, &trace[1..], update_sizes)
        },
        TypeVal::Struct(t, _, v) => {
            mutate_arg_from_trace(prng, v, &Some(Type::Struct(t.clone())), &trace[1..], update_sizes)
        }
        TypeVal::Array(t, _, v) => {
            // Defer to the contained vector v.
            mutate_arg_from_trace(prng, v, &Some(Type::Array(t.clone())), &trace[1..], update_sizes)
        }
    }
}

pub fn do_update_sizes(
    prng: &mut Prng,
    args: &mut Vec<TypeVal>,
    parent_typ: Option<Type>,
) {
    // cloning is expensive, check if we really need to first
    let args_copy: Vec<TypeVal> = args.clone();

    for arg in args.iter_mut() {
        match arg {
            TypeVal::Len(typ, _, ref mut val) => {
                if let Some(ref parent_typ)  = parent_typ {
                    mutate_size(prng, typ, &args_copy, parent_typ, val, true);
                }
            },
            TypeVal::Union(_, _, (_, ref mut v)) => {
                do_update_sizes(prng, v, None);
            },
            TypeVal::Struct(t, _, ref mut v) => {
                do_update_sizes(prng, v, Some(Type::Struct(t.clone())));
            },
            TypeVal::Array(t, _, ref mut v) => {
                do_update_sizes(prng, v, Some(Type::Array(t.clone())));
            },
            TypeVal::Ptr(_, _, ref mut v) => {
                do_update_sizes(prng, v, None);
            },
            TypeVal::Const(..)     |
            TypeVal::Int(..)       |
            TypeVal::Flags(..)     |
            TypeVal::Resource(..)  |
            TypeVal::Buffer(..) => { },
        }
    }
}


fn store_int(data: &mut [u8], val: u64, index: usize, width: usize) {
    // println!("{} {} {}", val, index, width);
    let val_bytes = val.to_le_bytes();
    match width {
        0 => {
            data[index] = val_bytes[0];
        },
        2 => {
            data[index] = val_bytes[0];
            data[index+1] = val_bytes[1];
        },
        4 => {
            data[index] = val_bytes[0];
            data[index+1] = val_bytes[1];
            data[index+2] = val_bytes[2];
            data[index+3] = val_bytes[3];
        },
        8 => {
            data[index] = val_bytes[0];
            data[index+1] = val_bytes[1];
            data[index+2] = val_bytes[2];
            data[index+3] = val_bytes[3];
            data[index+4] = val_bytes[4];
            data[index+5] = val_bytes[5];
            data[index+6] = val_bytes[6];
            data[index+7] = val_bytes[7];
        },
        _ => { }
    }
}

fn load_int(data: &mut [u8], index: usize, width: usize) -> u64 {
    let mut out = 0u64;
    match width {
        1 => {
            out |= data[index] as u64;
        },
        2 => {
            out |= data[index] as u64;
            out |= (data[index+1] as u64) << 8;
        },
        4 => {
            out |= data[index] as u64;
            out |= (data[index+1] as u64) << 8;
            out |= (data[index+2] as u64) << 16;
            out |= (data[index+3] as u64) << 24;
        },
        8 => {
            out |= data[index] as u64;
            out |= (data[index+1] as u64) << 8;
            out |= (data[index+2] as u64) << 16;
            out |= (data[index+3] as u64) << 24;
            out |= (data[index+4] as u64) << 32;
            out |= (data[index+5] as u64) << 40;
            out |= (data[index+6] as u64) << 48;
            out |= (data[index+7] as u64) << 56;
        },
        _ => { }
    }
    out
}


fn swap_int(v: u64, size: usize) -> u64 {
	match size {
        1 => v,
        2 => (v as u16).swap_bytes() as u64,
        4 => (v as u32).swap_bytes() as u64,
        8 => v.swap_bytes(),
        _ => {
            panic!("swapInt: bad size %v");
        }
    }
}
