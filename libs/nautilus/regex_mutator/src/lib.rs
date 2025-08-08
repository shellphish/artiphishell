// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

extern crate regex_syntax;

use rand::rng;
use rand::RngCore;

use regex_syntax::hir::{
    Class, ClassBytesRange, ClassUnicodeRange, Hir, Literal, RepetitionKind, RepetitionRange,
};

const MAX_BUFFER_SIZE: usize = 2 << 20; // 2MB limit

pub struct RomuPrng {
    xstate: u64,
    ystate: u64,
}

/// UTF-16 surrogate range start

const CHAR_SURROGATE_START: u32 = 0xD800;

/// UTF-16 surrogate range size

const CHAR_SURROGATE_LEN: u32 = 0xE000 - CHAR_SURROGATE_START;


/// Convert `char` to compressed `u32`

fn char_to_comp_u32(c: char) -> u32 {
    match c as u32 {
        c if c >= CHAR_SURROGATE_START => c - CHAR_SURROGATE_LEN,
        c => c,
    }
}

fn comp_u32_to_char(mut x: u32) -> Option<char> {
    if x >= CHAR_SURROGATE_START {
        x += CHAR_SURROGATE_LEN;
    }

    // SAFETY: x must not be in surrogate range or greater than char::MAX.
    // This relies on range constructors which accept char arguments.
    // Validity of input char values is assumed.
    unsafe { core::char::from_u32(x) }
}

impl RomuPrng {
    pub fn new(xstate: u64, ystate: u64) -> Self {
        return Self { xstate, ystate };
    }

    pub fn range(&mut self, min: usize, max: usize) -> usize {
        return ((self.next_u64() as usize) % (max - min)) + min;
    }

    pub fn new_from_u64(seed: u64) -> Self {
        let mut res = Self::new(seed, seed ^ 0xec77152282650854);
        for _ in 0..4 {
            res.next_u64();
        }
        return res;
    }

    pub fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    pub fn next_u64(&mut self) -> u64 {
        let xp = self.xstate;
        self.xstate = 15241094284759029579u64.wrapping_mul(self.ystate);
        self.ystate = self.ystate.wrapping_sub(xp);
        self.ystate = self.ystate.rotate_left(27);
        return xp;
    }
}

pub struct RegexScript {
    rng: RomuPrng,
    remaining: usize,
}

impl RegexScript {
    pub fn new(seed: u64) -> Self {
        let mut rng = RomuPrng::new_from_u64(seed);

        let len = if rng.next_u64() % 256 == 0 {
            rng.next_u64() % 0xffff
        } else {
            let len = 1 << (rng.next_u64() % 8);
            rng.next_u64() % len
        };
        RegexScript {
            rng,
            remaining: len as usize,
        }
    }

    pub fn get_mod(&mut self, val: usize) -> usize {
        if self.remaining == 0 {
            return 0;
        }
        return (self.rng.next_u32() as usize) % val;
    }

    pub fn get_range(&mut self, min: usize, max: usize) -> usize {
        return self.get_mod(max - min) + min;
    }
}

fn append_char(res: &mut Vec<u8>, chr: char) {
    let mut buf = [0; 4];
    res.extend_from_slice(chr.encode_utf8(&mut buf).as_bytes())
}

fn append_lit(res: &mut Vec<u8>, lit: &Literal) {
    use regex_syntax::hir::Literal::*;

    match lit {
        Unicode(chr) => append_char(res, *chr),
        Byte(b) => res.push(*b),
    }
}

fn append_unicode_range(res: &mut Vec<u8>, scr: &mut RegexScript, cls: &ClassUnicodeRange) {
    let low = char_to_comp_u32(cls.start());
    let high = char_to_comp_u32(cls.end());
    let c = scr.get_range(low as usize, (high + 1) as usize) as u32;
    if let Some(c) = comp_u32_to_char(c) {
        append_char(res, c);
        return;
    }

    panic!(
        "{}",
        format!("Could only generate invalid characters from range {}-{} after 4 tries. You should try to restrict the range to avoid invalid characters from being generated.", low, high)
    );
}

fn append_byte_range(res: &mut Vec<u8>, scr: &mut RegexScript, cls: &ClassBytesRange) {
    res.push(scr.get_range(cls.start() as usize, (cls.end() + 1) as usize) as u8);
}

fn append_class(res: &mut Vec<u8>, scr: &mut RegexScript, cls: &Class) {
    use regex_syntax::hir::Class::*;
    match cls {
        Unicode(cls) => {
            let rngs = cls.ranges();
            let rng = rngs[scr.get_mod(rngs.len())];
            append_unicode_range(res, scr, &rng);
        }
        Bytes(cls) => {
            let rngs = cls.ranges();
            let rng = rngs[scr.get_mod(rngs.len())];
            append_byte_range(res, scr, &rng);
        }
    }
}

fn get_length(scr: &mut RegexScript) -> usize {
    let bits = scr.get_mod(8);
    let len = scr.get_mod(2 << bits);
    return len.min(1024);
}

fn get_repetition_range(rep: &RepetitionRange, scr: &mut RegexScript) -> usize {
    use regex_syntax::hir::RepetitionRange::*;
    match rep {
        Exactly(a) => return *a as usize,
        AtLeast(a) => return get_length(scr) + (*a as usize),
        Bounded(a, b) => return scr.get_range(*a as usize, (*b as usize).min(1024)),
    }
}

fn get_repetitions(rep: &RepetitionKind, scr: &mut RegexScript) -> usize {
    use regex_syntax::hir::RepetitionKind::*;
    match rep {
        ZeroOrOne => return scr.get_mod(2),
        ZeroOrMore => return get_length(scr),
        OneOrMore => return 1 + get_length(scr),
        Range(rng) => get_repetition_range(rng, scr),
    }
}

pub fn generate(hir: &Hir, seed: u64) -> Vec<u8> {
    use regex_syntax::hir::HirKind::*;
    let mut scr = RegexScript::new(seed);
    let mut stack = vec![hir];
    let mut res = vec![];
    while stack.len() > 0 && res.len() < MAX_BUFFER_SIZE {  // Check size limit
        match stack.pop().unwrap().kind() {
            Empty => {}
            Literal(lit) => append_lit(&mut res, lit),
            Class(cls) => append_class(&mut res, &mut scr, cls),
            Anchor(_) => {}
            WordBoundary(_) => {}
            Repetition(rep) => {
                let num = get_repetitions(&rep.kind, &mut scr);
                for _ in 0..num {
                    stack.push(&rep.hir);
                }
            }
            Group(grp) => stack.push(&grp.hir),
            Concat(hirs) => hirs.iter().rev().for_each(|h| stack.push(h)),
            Alternation(hirs) => stack.push(&hirs[scr.get_mod(hirs.len())]),
        }
    }
    return res;
}

pub fn dumbass_generator_int(num_bits: usize) -> Vec<u8> {
    let num_bytes = (num_bits/8).min(MAX_BUFFER_SIZE);  // Cap at 10MB
    let mut out = vec![0u8; num_bytes];
    rng().fill_bytes(&mut out);
    out
}

pub fn dumbass_generator_bytes(num_bytes: usize) -> Vec<u8> {
    let capped_bytes = num_bytes.min(MAX_BUFFER_SIZE);  // Cap at 10MB
    let mut out = vec![0u8; capped_bytes];
    rng().fill_bytes(&mut out);
    out
}
