use cty::c_void;

// Credit goes to https://stackoverflow.com/questions/54999851/how-do-i-get-the-return-address-of-a-function
extern "C" {
    #[link_name = "llvm.returnaddress"]
    pub fn return_address(level: i32) -> *const c_void;
}

#[inline(always)]
pub fn retaddr() -> *const c_void {
    unsafe { return_address(0) }
}

#[inline(always)]
pub fn align_down(val: usize, align: usize) -> usize {
    val - val % align
}

#[inline(always)]
pub fn align_up(val: usize, align: usize) -> usize {
    align_down(val + align - 1, align)
}
