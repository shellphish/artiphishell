#![cfg(unix)]

use std::fmt::Debug;

// Uses custom hooks in Jazzer to mutate inputs

#[doc(hidden)]
pub trait RawJazzerCustomMutator {


    fn init() -> Self
    where
        Self: Sized;

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b [u8],
        max_size: usize,
        seed: u32
    ) -> Option<&'b [u8]>;

    fn crossover<'b, 's: 'b>(
        &'s mut self,
        buffer1: &'b [u8],
        buffer2: &'b [u8],
        out_size: usize,
        seed: u32
    ) -> Option<&'b [u8]>;

    fn post_process<'b, 's: 'b>(&'s mut self, buffer: &'b mut [u8]) -> Option<&'b [u8]>;
}

/// Wrappers for the custom mutator which provide the bridging between the C API and CustomJazzerMutator.
/// These wrappers are not intended to be used directly, rather export_mutator will use them to publish the custom mutator C API.
#[doc(hidden)]
pub mod wrappers {
    use std::sync::{Arc, Mutex};
    use std::{
        any::Any,
        panic::catch_unwind,
        process::abort,
        slice,
    };

    use crate::jazzer::RawJazzerCustomMutator;
    use crate::NautilusJazzerMutator;
    use lazy_static::lazy_static;

    // dont ask questions
    lazy_static! {
        static ref JAZZER_MUTATOR: Arc<Mutex<NautilusJazzerMutator>> = Arc::new(Mutex::new(NautilusJazzerMutator::init()));
    }

    /// panic handler called for every panic
    fn panic_handler(method: &str, panic_info: &Box<dyn Any + Send + 'static>) -> ! {
        use std::ops::Deref;
        let cause = panic_info.downcast_ref::<String>().map_or_else(
            || {
                panic_info
                    .downcast_ref::<&str>()
                    .copied()
                    .unwrap_or("<cause unknown>")
            },
            String::deref,
        );
        eprintln!("A panic occurred at {method}: {cause}");
        abort()
    }

    /// Internal function used in the macro
    /// # Safety
    ///
    /// May dereference all passed-in pointers.
    /// Should not be called manually, but will be called by `afl-fuzz`
    pub unsafe fn jazzer_custom_fuzz_<M: RawJazzerCustomMutator>(
        buf: *mut u8,
        buf_size: usize,
        max_size: usize,
        seed: u32
    ) -> usize {
        match catch_unwind(|| {
            assert!(!buf.is_null(), "null buf passed to jazzer_custom_fuzz");
            let mutator = &mut JAZZER_MUTATOR.lock().unwrap();

            let buffer = mutator.fuzz(slice::from_raw_parts(buf, buf_size), max_size, seed);

            if let Some(buffer) = buffer {
                if buffer.len() > max_size {
                    return 0;
                }
                let buff_slice_mut = slice::from_raw_parts_mut(buf, buffer.len());
                buff_slice_mut.copy_from_slice(&buffer);
                buff_slice_mut.len()
            } else {
                // return the input buffer with previous size to let libfuzzer skip this mutation attempt
                0
            }
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("jazzer_custom_fuzz", &err),
        }
    }

    /// Internal function used in the macro
    /// # Safety
    ///
    /// May dereference all passed-in pointers.
    /// Should not be called manually, but will be called by `afl-fuzz`
    pub unsafe fn jazzer_custom_crossover_<M: RawJazzerCustomMutator>(
        data1: *mut u8,
        size1: usize,
        data2: *mut u8,
        size2: usize,
        out: *mut u8,
        out_size: usize,
        seed: u32
    ) -> usize {
        match catch_unwind(|| {
            assert!(!data1.is_null(), "null buf passed to jazzer_custom_crossover");
            assert!(!data2.is_null(), "null buf passed to jazzer_custom_crossover");

            let mutator = &mut JAZZER_MUTATOR.lock().unwrap();

            let buff1_slice = slice::from_raw_parts(data1, size1);
            let buff2_slice = slice::from_raw_parts(data2, size2);

            let buffer = mutator.crossover(buff1_slice, buff2_slice, out_size, seed);

            if let Some(buffer) = buffer {
                if buffer.len() > out_size {
                    return 0;
                }
                let buff_slice_mut = slice::from_raw_parts_mut(out, buffer.len());
                buff_slice_mut.copy_from_slice(&buffer);
                buff_slice_mut.len()
            } else {
                // return the input buffer with previous size to let libfuzzer skip this mutation attempt
                0
            }
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("jazzer_custom_crossover", &err),
        }
    }

    /// Internal function used in the macro
    pub unsafe fn jazzer_custom_post_process_<M: RawJazzerCustomMutator>(
        buf: *mut u8,
        buf_size: usize,
        out_buf: *mut *const u8
    ) -> usize {
        match catch_unwind(|| {

            assert!(!buf.is_null(), "null buf passed to jazzer_custom_post_process");
            assert!(
                !out_buf.is_null(),
                "null out_buf passed to jazzer_custom_post_process"
            );
            let mutator = &mut JAZZER_MUTATOR.lock().unwrap();
            let buff_slice = slice::from_raw_parts_mut(buf, buf_size);
            if let Some(buffer) = mutator.post_process(buff_slice) {
                *out_buf = buffer.as_ptr();
                return buffer.len();
            }
            0
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("jazzer_custom_post_process", &err),
        }
    }
}

#[macro_export]
macro_rules! export_jazzer_mutator {
    ($mutator_type:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn customMutatorHook(
            buf: *mut u8,
            buf_size: usize,
            max_size: usize,
            seed: u32
        ) -> usize {
            $crate::jazzer::wrappers::jazzer_custom_fuzz_::<$mutator_type>(
                buf,
                buf_size,
                max_size,
                seed
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn crossOverHook(
            data1: *mut u8,
            size1: usize,
            data2: *mut u8,
            size2: usize,
            out: *mut u8,
            out_size: usize,
            seed: u32
        ) -> usize {
            $crate::jazzer::wrappers::jazzer_custom_crossover_::<$mutator_type>(
                data1,
                size1,
                data2,
                size2,
                out,
                out_size,
                seed
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn testOneInputHook(
            buf: *mut u8,
            buf_size: usize,
            out_buf: *mut *const u8
        ) -> usize {
            $crate::jazzer::wrappers::jazzer_custom_post_process_::<$mutator_type>(buf, buf_size, out_buf)
        }
    };
}

/// A custom mutator.
/// [`CustomJazzerMutator::handle_error`] will be called in case any method returns an [`Result::Err`].
#[allow(unused_variables)]
#[allow(clippy::missing_errors_doc)]
pub trait CustomJazzerMutator {
    /// The error type. All methods must return the same error type.
    type Error: Debug;

    /// The method which handles errors.
    /// By default, this method will log the error to stderr if the environment variable "`AFL_CUSTOM_MUTATOR_DEBUG`" is set and non-empty.
    /// After logging the error, execution will continue on a best-effort basis.
    ///
    /// This default behaviour can be customized by implementing this method.
    fn handle_error(err: Self::Error) {
        if std::env::var("JAZZER_CUSTOM_MUTATOR_DEBUG")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            eprintln!("Error in custom mutator: {err:?}");
        }
    }

    fn init() -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b [u8],
        max_size: usize,
        seed: u32
    ) -> Result<Option<&'b [u8]>, Self::Error>;

    fn crossover<'b, 's: 'b>(
        &'s mut self,
        buffer1: &'b [u8],
        buffer2: &'b [u8],
        out_size: usize,
        seed: u32
    ) -> Result<Option<&'b [u8]>, Self::Error>;

    fn post_process<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        Ok(Some(buffer))
    }
}

impl<M> RawJazzerCustomMutator for M
where
    M: CustomJazzerMutator,
    M::Error: Debug,
{


    fn init() -> Self
    where
        Self: Sized,
    {
        match Self::init() {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                panic!("Error in afl_custom_init")
            }
        }
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b [u8],
        max_size: usize,
        seed: u32
    ) -> Option<&'b [u8]> {
        match self.fuzz(buffer, max_size, seed) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                None
            }
        }
    }

    fn crossover<'b, 's: 'b>(
        &'s mut self,
        buffer1: &'b [u8],
        buffer2: &'b [u8],
        out_size: usize,
        seed: u32
    ) -> Option<&'b [u8]> {
        match self.crossover(buffer1, buffer2, out_size, seed) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                None
            }
        }
    }

    fn post_process<'b, 's: 'b>(&'s mut self, buffer: &'b mut [u8]) -> Option<&'b [u8]> {
        match self.post_process(buffer) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                None
            }
        }
    }
}
