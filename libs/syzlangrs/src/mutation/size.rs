use crate::serialization::{SerializerHeap, BitVec, handle_value};
use crate::grammar::{types::{self, IntTypeCommon}, syscalls::TypeVal};
use crate::rng::Prng;

pub fn mutate_size(
    prng: &mut Prng,
    typ: &types::Len,
    parent_args: &Vec<TypeVal>,
    parent_typ: &types::Type,
    val: &mut u64,
    exact: bool
) -> bool {
    // find the type pointed to by len
    //let found = None;
    let is_bytesize: bool = typ.name == "bytesize";

    let mut type_size = 0u64;

	if !exact && prng.one_of(100) {
		*val = prng.get_u64();
		return true
	}

	if !exact && prng.bin() {
		// Small adjustment to trigger missed size checks.
		if *val != 0 && prng.bin() {
            let upper = (*val).checked_sub(1).unwrap_or(*val);
			*val = prng.rand_range_int(0, upper, typ.bitsize(), 0)
		} else {
            // println!("val: {:x}", val);
            let lower = (*val).checked_add(1).unwrap_or(*val);
            let upper = (*val).checked_add(100).unwrap_or(u64::MAX);
			*val = prng.rand_range_int(lower, upper, typ.bitsize(), 0)
		}
		return true
	}

    if typ.path.len() == 1 {
        if let types::Type::Struct(struc) = parent_typ {
            for (idx, field) in struc.fields.iter().enumerate() {
                if typ.path[0] == field.name {
                    if is_bytesize ||
                        !matches!(
                            &parent_args[idx],
                            TypeVal::Array(..) |
                            TypeVal::Buffer(..)
                        ) {
                        let mut bv: BitVec = BitVec::new();
                        let mut heap = SerializerHeap { base: 0, in_use: 0, };
                        handle_value(&parent_args[idx], &mut heap, &mut bv);
                        type_size = bv.len() as u64;
                    } else {
                        match &parent_args[idx] {
                            TypeVal::Array(_, _, v) => {
                                //println!("ARRAY SIZE: {}", v.len());
                                type_size = v.len() as u64;
                            }
                            TypeVal::Buffer(_, _, v) => {
                                type_size = v.len() as u64;
                            }
                            _ => { println!("WAHT {:?}", parent_args[idx]); unimplemented!() }
                        }
                    }
                }
            }
        }
    }

    if exact {
        *val = type_size;
        //println!("exact: {:x}", type_size);
        return true;
    }

	let delta: u64 = 1000 - prng.biased_rand(1000, 10);
    if prng.bin() {
        *val = type_size.saturating_add(delta);
    } else {
        *val = type_size.saturating_sub(delta);
    }
	true
}
