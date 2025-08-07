
// Credit goes to https://stackoverflow.com/questions/54999851/how-do-i-get-the-return-address-of-a-function
extern {
    #[link_name = "llvm.returnaddress"]
    pub fn return_address(level: i32) -> *const u8;
}
macro_rules! retaddr {
    () => {
        unsafe {
            util::return_address(0)
        }
    };
}
