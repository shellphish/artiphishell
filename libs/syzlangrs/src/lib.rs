use std::collections::hash_map::DefaultHasher;
pub mod serialization;
pub mod mutation;
pub mod grammar;
pub mod rng;

use std::hash::{Hash, Hasher};

#[derive(Clone, Debug)]
pub struct Corpus {
    pub progs: Vec<Prog>
}

#[derive(Clone, Debug, Default)]
pub struct Prog {
    /// contains a syscall and optionally the associated coverage
    pub syscalls: Vec<(grammar::syscalls::Syscall, Option<u64>)>,

    /// Overall coverage for the prog
    pub coverage: u64,

    /// A user defined tag for this program
    pub tag: u64
}

impl Hash for Prog {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for (call, _) in &self.syscalls {
            let (_resources, args) = serialization::serialize_call(
                call,
                0,
                &vec![]
            );
            for a in args {
                match a {
                    serialization::CallResult::Pointer(v, d) => {
                        v.hash(state);
                        d.hash(state);
                    },
                    serialization::CallResult::Integer(v) => {
                        v.hash(state);
                    }
                }
            }
        }
    }
}

impl Eq for Prog { }

impl PartialEq for Prog {
    fn eq(&self, other: &Self) -> bool {
        if self.syscalls.len() != other.syscalls.len() {
            return false;
        }
        let mut self_hasher = DefaultHasher::new();
        self.hash(&mut self_hasher);
        let self_hash = self_hasher.finish();

        let mut other_hasher = DefaultHasher::new();
        other.hash(&mut other_hasher);
        let other_hash = other_hasher.finish();
        self_hash == other_hash
    }
}


#[cfg(test)]
mod tests {
    use std::time::Instant;

    use self::grammar::types::{Dir, Field};

    use super::*;
    use crate::grammar::{syscalls::{SyscallDef, TypeVal}, types::{self, IntKind, Type}};
    use super::grammar::syscalls::Syscall;

    fn hexdump(data: &[u8]) {
        for (i, chunk) in data.chunks(16).enumerate() {
            // Print the offset
            print!("{:08x}  ", i * 16);

            // Print the hex representation
            for byte in chunk {
                print!("{:02x} ", byte);
            }

            // Print extra spaces if the chunk is less than 16 bytes
            if chunk.len() < 16 {
                for _ in 0..(16 - chunk.len()) {
                    print!("   ");
                }
            }

            // Print the ASCII representation
            print!(" |");
            for byte in chunk {
                if byte.is_ascii_graphic() {
                    print!("{}", *byte as char);
                } else {
                    print!(".");
                }
            }
            println!("|");
        }
    }

    #[test]
    fn rng() {
        let mut prng = rng::Prng { a: 0x1337 };
        let _: u8  = prng.get_u8();
        let _: u32 = prng.get_u32();
        let _: u64 = prng.get_u64();
    }

    #[test]
    fn rand_sys() {
        let mut prng = rng::Prng { a: 0x1337 };

        let now = Instant::now();
        let _syscall = Syscall::new(&mut prng, vec![]);
        let elapsed = now.elapsed();

        dbg!("rand_sys", elapsed);//, syscall);

        let now = Instant::now();
        let syscall = Syscall::new(&mut prng, vec![]);
        dbg!(&syscall);
        if let Some(syscall) = &syscall {
            let (resources, args) = serialization::serialize_call(
                syscall,
                0x4000,
                &vec![]
            );
            dbg!(args);
        }
        let elapsed = now.elapsed();

        dbg!("rand_sys", elapsed);
    }

    #[test]
    fn mutate_sys() {
        let mut prng = rng::Prng { a: 0x1337 };

        // for _ in 0..1000 {
        //     let syscall = Syscall::new(
        //         &mut prng, vec![]
        //     ).expect("Syscall was None");
        //     //dbg!(&syscall);
        // }

        let syscall = Syscall::new(
            &mut prng, vec![]
        ).expect("Syscall was None");
        dbg!(&syscall);

        let (resources, args) = serialization::serialize_call(
            &syscall,
            0x4000,
            &vec![]
        );
        if let serialization::CallResult::Pointer(_, p) = &args[0] {
            hexdump(p);
        }

        //let mut avail_resources = vec![];
        //for sys in SYSCALL_TABLE {
        //    if sys.name == "socket" {
        //        prog.push(
        //            (Syscall::new_from_def(&mut prng, sys, vec![]).expect(""), None)
        //        );
        //    }
        //}

        //for (sysc, _) in &prog {
        //    if let Some(Type::Resource(rsrc)) = &sysc.def.ret {
        //        avail_resources.push(rsrc.desc.clone());
        //    }
        //}

        //for sys in SYSCALL_TABLE {
        //    if sys.name == "sendmsg$TIPC_CMD_ENABLE_BEARER" {
        //        prog.push(
        //            (Syscall::new_from_def(&mut prng, sys, avail_resources.clone()).expect(""), None)
        //        );
        //    }
        //}

        // let mut corpus = Corpus { progs: vec![] };

        // let mut prog = Prog { syscalls: vec![(syscall, None)], coverage: 0 };
        // corpus.progs.push(prog.clone());

        // let now = Instant::now();
        // for _ in 0..10000 {
        //     mutation::mutate(&mut prng, &mut corpus, &mut prog);
        // }
        // let elapsed = now.elapsed();

        //dbg!(&prog);

        //dbg!("mutate_sys", elapsed);
    }

    pub const TEST_INT: types::Int = types::Int {
        name: "test_int",
        size: 4,
        align: 4,
        is_varlen: false,
        kind: IntKind::IntPlain,
        arg_format: types::BinaryFormat::FormatNative,
        bitfield_len: 0,
        bitfield_off: 0,
    };

    pub const TEST_PTR_INT: types::Ptr = types::Ptr {
        name: "test_ptr_int",
        dir: types::Dir::DirIn,
        align: 8,
        is_varlen: false,
        size: 8,
        elem: &Type::Buffer(TEST_BUF),
    };

    pub const TEST_PTR_BUF: types::Ptr = types::Ptr {
        name: "test_ptr_buf",
        dir: types::Dir::DirIn,
        align: 0,
        is_varlen: false,
        size: 8,
        elem: &Type::Buffer(TEST_BUF),
    };

    pub const TEST_BUF: types::Buffer = types::Buffer {
        name: "test_buf",
        size: 8,
        align: 0,
        kind: types::BufferKind::BufferBlobRand,
        is_varlen: true,
        noz: true,
        values: &["testing"],
        range_begin: 0,
        range_end: 0,
    };

    pub const TEST_STRUCT_STRUCT: types::Struct = types::Struct {
        name: "test_struct",
        align: 8,
        is_varlen: false,
        fields: &[
            Field {
                dir: Dir::DirIn,
                has_dir: false,
                name: "asdf",
                typ: types::FieldType::Type(
                    Type::Struct(TEST_STRUCT)
                )
            },
            Field {
                dir: Dir::DirIn,
                has_dir: false,
                name: "bsdf",
                typ: types::FieldType::Type(
                    Type::Int(TEST_INT)
                )
            },
        ],
        size: 123,
    };

    pub const TEST_STRUCT: types::Struct = types::Struct {
        name: "test_struct",
        align: 8,
        is_varlen: false,
        fields: &[
            Field {
                dir: Dir::DirIn,
                has_dir: false,
                name: "asdf",
                typ: types::FieldType::Type(
                    Type::Int(TEST_INT)
                )
            },
        ],
        size: 123,
    };

    pub const TEST_PTR_STRUCT_STRUCT: types::Ptr = types::Ptr {
        name: "test_ptr_buf",
        dir: types::Dir::DirIn,
        align: 0,
        size: 8,
        is_varlen: false,
        elem: &Type::Struct(TEST_STRUCT_STRUCT),
    };

    pub const TEST_BITFIELD_1: types::Int = types::Int {
        name: "test_bitfield_1",
        size: 0,
        align: 4,
        is_varlen: false,
        kind: IntKind::IntPlain,
        arg_format: types::BinaryFormat::FormatBigEndian,
        bitfield_len: 16,
        bitfield_off: 0,
    };

    pub const TEST_BITFIELD_2: types::Int = types::Int {
        name: "test_bitfield_2",
        size: 4,
        align: 4,
        is_varlen: false,
        kind: IntKind::IntPlain,
        arg_format: types::BinaryFormat::FormatBigEndian,
        bitfield_len: 8,
        bitfield_off: 16,
    };

    pub const TEST_BITFIELD_STRUCT: types::Struct = types::Struct {
        name: "test_struct",
        align: 8,
        is_varlen: false,
        fields: &[
            Field {
                dir: Dir::DirIn,
                has_dir: false,
                name: "bf1",
                typ: types::FieldType::Type(
                    Type::Int(TEST_BITFIELD_1)
                )
            },
            Field {
                dir: Dir::DirIn,
                has_dir: false,
                name: "bf2",
                typ: types::FieldType::Type(
                    Type::Int(TEST_BITFIELD_1)
                )
            },
        ],
        size: 4,
    };

    pub const TEST_BITFIELD_PTR: types::Ptr = types::Ptr {
        name: "test_bitfield_struct",
        dir: types::Dir::DirIn,
        align: 0,
        is_varlen: false,
        size: 8,
        elem: &Type::Struct(TEST_BITFIELD_STRUCT),
    };

    pub const SERIALIZATION_TESTCALL_TABLE: &[SyscallDef] = &[
        SyscallDef {
            id: 0,
            name: "test",
            args: &[
                ("test1", Type::Int(TEST_INT)),
                ("test_ptr_int", Type::Ptr(TEST_PTR_INT)),
                ("test_ptr_buf", Type::Ptr(TEST_PTR_BUF)),
                ("test_ptr_struct_struct", Type::Ptr(TEST_PTR_STRUCT_STRUCT)),
                ("test_bitfield_ptr", Type::Ptr(TEST_BITFIELD_PTR)),
            ],
            ret: None
        }
    ];

    #[test]
    fn serialization() {
        let test_call = Syscall {
            def: &SERIALIZATION_TESTCALL_TABLE[0],
            args: [
                TypeVal::Int(TEST_INT, types::Dir::DirIn, 8),
                TypeVal::Ptr(TEST_PTR_INT, types::Dir::DirIn, vec![
                    TypeVal::Int(
                        TEST_INT,
                        types::Dir::DirIn,
                        1337
                    ),
                ]),
                TypeVal::Ptr(TEST_PTR_BUF, types::Dir::DirIn, vec![
                    TypeVal::Buffer(
                        TEST_BUF,
                        types::Dir::DirIn,
                        "TESTING".as_bytes().to_vec()
                    ),
                ]),
                TypeVal::Ptr(TEST_PTR_STRUCT_STRUCT, types::Dir::DirIn, vec![
                    TypeVal::Struct(
                        TEST_STRUCT_STRUCT,
                        types::Dir::DirIn,
                        vec![
                            TypeVal::Struct(
                                TEST_STRUCT,
                                types::Dir::DirIn,
                                vec![
                                    TypeVal::Int(
                                        TEST_INT,
                                        types::Dir::DirIn,
                                        1337
                                    )
                                ]
                            ),
                            TypeVal::Int(
                                TEST_INT,
                                types::Dir::DirIn,
                                1337
                            ),
                        ]
                    ),
                ]),
                TypeVal::Ptr(TEST_BITFIELD_PTR, types::Dir::DirIn, vec![
                    TypeVal::Struct(
                        TEST_BITFIELD_STRUCT,
                        types::Dir::DirIn,
                        vec![
                            TypeVal::Int(
                                TEST_BITFIELD_1,
                                types::Dir::DirIn,
                                0x1337
                            ),
                            TypeVal::Int(
                                TEST_BITFIELD_2,
                                types::Dir::DirIn,
                                0x13
                            ),
                        ]
                    ),
                ]),
            ].to_vec(),
            requires: vec![]
        };

        let (resources, args) = serialization::serialize_call(
            &test_call,
            0x4000,
            &vec![]
        );
        dbg!(resources, args);
    }

    pub const TEST_ARRAY_PTR: types::Ptr = types::Ptr {
        name: "test_array_ptr",
        dir: types::Dir::DirIn,
        align: 0,
        is_varlen: false,
        size: 8,
        elem: &Type::Array(TEST_ARRAY),
    };

    pub const TEST_ARRAY: types::Array = types::Array {
        name: "test_array_ptr",
        align: 0,
        size: 8,
        elem: &Type::Int(TEST_INT),
        kind: types::ArrayKind::ArrayRandLen,
        is_varlen: true,
    };

    pub const ARRAY_TESTCALL_TABLE: &[SyscallDef] = &[
        SyscallDef {
            id: 0,
            name: "syz_test_array",
            args: &[
                ("test_array_ptr", Type::Ptr(TEST_ARRAY_PTR)),
            ],
            ret: None
        }
    ];

    #[test]
    fn ser_array() {
        let test_call = Syscall {
            def: &ARRAY_TESTCALL_TABLE[0],
            args: [
                TypeVal::Ptr(TEST_ARRAY_PTR, types::Dir::DirIn, vec![
                    TypeVal::Array(
                        TEST_ARRAY,
                        types::Dir::DirIn,
                        vec![
                            TypeVal::Int(
                                TEST_INT,
                                types::Dir::DirIn,
                                0x0101
                            ),
                            TypeVal::Int(
                                TEST_INT,
                                types::Dir::DirIn,
                                0xd25
                            ),
                            TypeVal::Int(
                                TEST_INT,
                                types::Dir::DirIn,
                                0x0202
                            )
                        ]
                    ),
                ]),
            ].to_vec(),
            requires: vec![]
        };

        let args = serialization::serialize_call(
            &test_call,
            0x4000,
            &vec![]
        );
        dbg!(args);
    }
}
