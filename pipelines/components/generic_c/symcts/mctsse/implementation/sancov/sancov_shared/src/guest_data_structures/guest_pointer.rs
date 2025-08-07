use std::{fmt, hash::Hash, marker::PhantomData};

#[derive(Eq, Copy, Clone)]
pub struct GuestPointer<T> {
    val: usize,
    phantom: PhantomData<T>,
}

impl<T> GuestPointer<*mut T> {
    pub fn new(t: usize) -> GuestPointer<*mut T> {
        GuestPointer {
            val: t,
            phantom: Default::default(),
        }
    }
    pub fn cast<U>(&self) -> GuestPointer<*mut U> {
        GuestPointer::<*mut U>::new(self.val)
    }
    pub fn as_const(&self) -> GuestPointer<*const T> {
        GuestPointer::<*const T>::new(self.val)
    }
    pub fn pointer(&self) -> *mut T {
        self.val as *mut T
    }
    pub fn offset(&self, offset: isize) -> GuestPointer<*mut T> {
        GuestPointer::<*mut T>::new(unsafe { self.pointer().offset(offset) } as usize)
    }
}
impl<T> GuestPointer<*const T> {
    pub fn new(t: usize) -> GuestPointer<*const T> {
        GuestPointer {
            val: t,
            phantom: Default::default(),
        }
    }
    pub fn cast<U>(&self) -> GuestPointer<*const U> {
        GuestPointer::<*const U>::new(self.val)
    }
    pub fn as_mut(&self) -> GuestPointer<*mut T> {
        GuestPointer::<*mut T>::new(self.val)
    }
    pub fn pointer(&self) -> *const T {
        self.val as *const T
    }
    pub fn offset(&self, offset: isize) -> GuestPointer<*const T> {
        GuestPointer::<*const T>::new(unsafe { self.pointer().offset(offset) } as usize)
    }
}
impl<T> GuestPointer<T> {
    pub fn as_usize(&self) -> usize {
        self.val
    }
}

impl<T> PartialOrd for GuestPointer<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.val.partial_cmp(&other.val)
    }
}
impl<T> PartialEq for GuestPointer<T> {
    fn eq(&self, other: &Self) -> bool {
        self.val == other.val
    }
}

impl<T> Hash for GuestPointer<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.val.hash(state);
    }
}

impl<T> fmt::Debug for GuestPointer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("0x{:x}", self.val))
    }
}

impl<T> From<GuestPointer<T>> for usize {
    fn from(t: GuestPointer<T>) -> usize {
        t.val
    }
}
impl<T> From<*mut T> for GuestPointer<*mut T> {
    fn from(t: *mut T) -> GuestPointer<*mut T> {
        (t as usize).into()
    }
}
impl<T> From<*const T> for GuestPointer<*const T> {
    fn from(t: *const T) -> GuestPointer<*const T> {
        (t as usize).into()
    }
}
impl<T> From<usize> for GuestPointer<*const T> {
    fn from(t: usize) -> GuestPointer<*const T> {
        GuestPointer::<*const T>::new(t)
    }
}
impl<T> From<usize> for GuestPointer<*mut T> {
    fn from(t: usize) -> GuestPointer<*mut T> {
        GuestPointer::<*mut T>::new(t)
    }
}
