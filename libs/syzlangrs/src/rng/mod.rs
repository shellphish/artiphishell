#[derive(Clone)]
pub struct Prng {
    pub a: u32,
}

impl Prng {
    pub fn get_next(&mut self) -> u32 {
        let mut x: u32 = self.a;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.a = x;
        x
    }

    pub fn get_u32(&mut self) -> u32 {
        let x: u32 = self.get_next();
        x
    }

    pub fn get_u64(&mut self) -> u64 {
        let x: u64 = (self.get_next() as u64) << 32 | self.get_next() as u64;
        x
    }

    pub fn get_u16(&mut self) -> u16 {
        let x: u16 = (self.get_next() & 0xffff) as u16;
        x
    }

    pub fn get_u8(&mut self) -> u8 {
        let x: u8 = (self.get_next() & 0xff) as u8;
        x
    }

    pub fn one_of(&mut self, n: u64) -> bool {
        let x: bool = (self.get_u64() % n) == 1;
        x
    }

    pub fn int_n(&mut self, n: u64) -> i64 {
        let x: i64 = ((self.get_u64() & ((1<<63)-1)) % n) as i64;
        x
    }

    pub fn uint_n(&mut self, n: u64) -> u64 {
        let x: u64 = (self.get_u64() & ((1<<63)-1)) % n;
        x
    }

    pub fn bin(&mut self) -> bool {
        let x: bool = self.get_u32() & 1 == 1;
        x
    }

    pub fn biased_rand(&mut self, n: u64, iters: usize) -> u64 {
        let mut res = 0;
        for _ in 0..iters {
            let x: u64 = self.uint_n(n);
            if x > res {
                res = x;
            }
        }
        if res >= n { panic!("result was >= n") }
        res
    }

    pub fn flags(&mut self, vv: &[u64], bitmask: bool, old_val: u64) -> u64 {
        // Get these simpler cases out of the way first.
        // Once in a while we want to return completely random values,
        // or 0 which is frequently special.
        if self.one_of(100) {
            return self.get_u64()
        }
        if self.one_of(50) {
            return 0
        }
        if !bitmask && old_val != 0 && self.one_of(100) {
            // Slightly increment/decrement the old value.
            // This is especially important during mutation when len(vv) == 1,
            // otherwise in that case we produce almost no randomness
            // (the value is always mutated to 0).
            let mut inc = 1u64;
            if self.bin() {
                inc = u64::MAX;
            }
            let mut v = old_val.saturating_add(inc);
            while self.bin() {
                v = v.saturating_add(inc);
            }
            return v
        }
        if vv.len() == 1 {
            // This usually means that value or 0,
            // at least that's our best (and only) bet.
            if self.bin() {
                return 0
            }
            return vv[0]
        }
        if !bitmask && !self.one_of(10) {
            // Enumeration, so just choose one of the values.
            return vv[self.uint_n(vv.len() as u64) as usize]
        }
        if self.one_of(vv.len() as u64 + 4) {
            return 0
        }
        // Flip rand bits. Do this for non-bitmask sometimes
        // because we may have detected bitmask incorrectly for complex cases
        // (e.g. part of the vlaue is bitmask and another is not).
        let mut v = old_val;
        if v != 0 && self.one_of(10) {
            v = 0; // Ignore the old value sometimes.
        }
        let mut tryct = 0;
        while tryct < 10 && (v == 0 || !self.one_of(3)) {
            let mut flag = vv[self.uint_n(vv.len() as u64) as usize];
            if self.one_of(20) {
                // Try choosing adjacent bit values in case we forgot
                // to add all relevant flags to the descriptions.
                if self.bin() {
                    flag >>= 1;
                } else {
                    flag <<= 1;
                }
            }
            v ^= flag;
            tryct += 1;
        }
        v
    }

    pub fn rand_range_int(
        &mut self,
        begin: u64,
        end: u64,
        bit_size: u64,
        align: u64
    ) -> u64 {
        let mut end = end;
        if self.one_of(100) {
            return self.uint_n(bit_size);
        }
        if align != 0 {
            if begin == 0 && end == u64::MAX {
                end = 1 << (bit_size - 1);
            }
            let end_align = (end - begin) / align;
            return begin + self.rand_range_int(0, end_align, bit_size, 0) * align;
        }
        begin + (self.get_u64() % (end - begin + 1))
    }

    pub fn rand_filename_len(&mut self) -> i64 {
        let mut off = self.biased_rand(10, 5);
        if self.bin() {
            off = !off;
        }
        let lens = [256, 512, 4096][self.uint_n(3) as usize];
        let mut res: i64 = (lens + off) as i64;
        if res < 0 {
            res = 0;
        }
        res
    }
}
