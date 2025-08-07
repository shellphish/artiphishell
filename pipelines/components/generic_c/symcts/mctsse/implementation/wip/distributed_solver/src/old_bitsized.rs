
pub trait Bitsized {
    fn bits(&self) -> usize;
}

impl Bitsized for u128 { fn bits(&self) -> usize { return 128;} }
impl Bitsized for u64 { fn bits(&self) -> usize { return 64;} }
impl Bitsized for u32 { fn bits(&self) -> usize { return 32;} }
impl Bitsized for u16 { fn bits(&self) -> usize { return 16;} }
impl Bitsized for u8  { fn bits(&self) -> usize { return 8;} }

impl Bitsized for i128 { fn bits(&self) -> usize { return 128;} }
impl Bitsized for i64 { fn bits(&self) -> usize { return 64;} }
impl Bitsized for i32 { fn bits(&self) -> usize { return 32;} }
impl Bitsized for i16 { fn bits(&self) -> usize { return 16;} }
impl Bitsized for i8  { fn bits(&self) -> usize { return 8;} }