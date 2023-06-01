#![feature(maybe_uninit_as_bytes)]

use core::{mem::{MaybeUninit, size_of}, slice};
use embedded_storage::ReadStorage;

/// AsRaw can be added to anything, that if it has a C representation can be
/// directly manipulated as a sequence of bytes. This is only safe if the types
/// used are valid with any value that is given in the bytes.
pub trait AsRaw: Sized {
    fn as_raw(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }

    fn as_raw_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self as *mut _ as *mut u8, size_of::<Self>()) }
    }

    // Build one of these by copying the data out of a buffer.
    /*
    fn from_bytes(buf: &[u8]) -> Self {
        let mut item = MaybeUninit::<Self>::uninit();
        {
            let dbuf = item.as_bytes_mut();
            let src = unsafe { mem::transmute::<_, &[MaybeUninit<u8>]>(buf) };
            dbuf.clone_from_slice(src);
        }
        unsafe { item.assume_init() }
    }
    */
}

pub trait ReadStorageExt: Sized {
    type Error;
    fn from_storage<R: AsRaw>(&mut self, offset: u32) -> std::result::Result<R, Self::Error>;
}

/// Anything that implements AsRaw can be directly read out of storage.
impl<T: ReadStorage> ReadStorageExt for T {
    type Error = T::Error;

    fn from_storage<R: AsRaw>(&mut self, offset: u32) -> std::result::Result<R, Self::Error> {
        // TODO: Some experimental features of the compiler may allow this to be
        // done as an array with const, but for now, just alloc.

        let mut item = MaybeUninit::<R>::uninit();
        {
            let src = item.as_bytes_mut();
            let buf = unsafe { core::mem::transmute::<_, &mut [u8]>(src) };
            self.read(offset, buf)?;
        }
        Ok(unsafe { item.assume_init() })
    }
}
