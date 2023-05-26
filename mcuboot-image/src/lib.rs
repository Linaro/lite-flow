#![feature(maybe_uninit_as_bytes)]

use thiserror::Error;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

// For now, just use this.
type Result<T> = anyhow::Result<T>;

#[cfg(test)]
mod tests {
    use core::slice;
    use std::{mem::{self, MaybeUninit, size_of}, path::Path};

    use embedded_storage::ReadStorage;

    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn load_image() {
        let mut image = LoadedFlash::from_file("signed.bin").unwrap();
        // Load in an image, and make sure we can decode the header.
        // let image = std::fs::read("signed.bin").unwrap();
        println!("Image size: {}", image.capacity());

        // View this as an aligned thingy.
        /*
        let (head, body, _tail) = unsafe { image[0..32].align_to::<Header>() };
        assert!(head.is_empty(), "Buffer was not aligned");
        assert!(body.len() > 0, "Insufficient data");
        println!("Image: {:#x?}", body[0]);
        */

        // Try this again, with a copy.
        // let mut head: Header = /* todo unsafe uninitialized */ Default::default();
        /*
        let mut head = unsafe { mem::MaybeUninit::<Header>::uninit().assume_init()} ;
        {
            let buf = head.as_raw_mut();
            buf.clone_from_slice(&image[0..32]);
        }
        */

        // This might be the best upcoming way of doing this, although this depends on nightly.
        /*
        let mut head = mem::MaybeUninit::<Header>::uninit();
        {
            let buf = head.as_bytes_mut();
            let src = unsafe { mem::transmute::<_, &[MaybeUninit<u8>]>(&image[0..32]) };
            buf.clone_from_slice(src);
        }
        let head = unsafe { head.assume_init() };
        println!("Imageb: {:#x?}", head);
        */

        // let head: Header = AsRaw::from_bytes(&image[0..32]);
        let head: Header = image.from_storage(0).unwrap();
        println!("Imagec: {:#x?}", head);
        println!("TLV: {:x?}", head.tlv_base());
        // let _ = Tlv::new(&head, &image);
        panic!("TODO");
    }

    #[repr(C)]
    #[derive(Debug, Default)]
    struct Header {
        magic: u32,
        load_addr: u32,
        hdr_size: u16,
        protect_tlv_size: u16,
        img_size: u32,
        flags: u32,
        version: Version,
        pad1: u32,
    }
    impl AsRaw for Header {}

    #[repr(C)]
    #[derive(Debug, Default)]
    struct Version {
        major: u8,
        minor: u8,
        revision: u16,
        build_num: u32,
    }

    impl Header {
        pub fn tlv_base(&self) -> usize {
            (self.hdr_size as u32 + self.img_size) as usize
        }
    }

    /// View this type as a byte array. This is technically unsound, but by
    /// keeping the unsafe encapsulated here, the unsoundness should be
    /// relegated to just the valid contents of the fields within the structure.
    /// As such, this should generally only be implemented for types that are
    /// just low level types.
    trait AsRaw : Sized {
        fn as_raw(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self as *const _ as *const u8,
                                           mem::size_of::<Self>()) }
        }

        fn as_raw_mut(&mut self) -> &mut[u8] {
            unsafe { slice::from_raw_parts_mut(self as *mut _ as *mut u8,
                                               mem::size_of::<Self>()) }
        }

        // Build one of these by copying the data out of a buffer.
        fn from_bytes(buf: &[u8]) -> Self {
            let mut item = MaybeUninit::<Self>::uninit();
            {
                let dbuf = item.as_bytes_mut();
                let src = unsafe { mem::transmute::<_, &[MaybeUninit<u8>]>(buf) };
                dbuf.clone_from_slice(src);
            }
            unsafe { item.assume_init() }
        }
    }

    // AsRaw things can be read.
    trait ReadStorageExt {
        fn from_storage<R: AsRaw>(&mut self, offset: u32) -> Result<R>;
    }

    impl ReadStorageExt for LoadedFlash {
        fn from_storage<R: AsRaw>(&mut self, offset: u32) -> Result<R> {
            // TODO: Some experimental features of the compiler may allow this
            // to be done as an array with const, but for now, just alloc.
            // let mut buf = [0u8; size_of::<R>()];
            let mut buf = vec![0u8; size_of::<R>()];
            self.read(offset, &mut buf)?;
            Ok(AsRaw::from_bytes(&buf))
        }
    }

    /// Tracker for the TLV.  The slice are the raw bytes of the TLV.
    struct Tlv<'a> {
        data: &'a [u8],
        protect_size: usize,
    }

    impl<'a> Tlv<'a> {
        fn new<'n>(head: &Header, image: &'n [u8]) -> Tlv<'n> {
            let base = head.tlv_base();
            let tlv_head: TlvHead = AsRaw::from_bytes(&image[base..base + size_of::<TlvHead>()]);
            println!("Head: {:#x?}", tlv_head);
            unimplemented!()
        }
    }

    #[repr(C)]
    #[derive(Debug)]
    struct TlvHead {
        tag: u16,
        length: u16,
    }
    impl AsRaw for TlvHead {}

    #[derive(Error, Debug)]
    enum FlashError {
        #[error("Read past device bounds")]
        ReadBound,
    }
    type FlashResult<T> = std::result::Result<T, FlashError>;

    /// A simulated flash device loaded from an image.
    struct LoadedFlash {
        data: Vec<u8>,
    }

    impl LoadedFlash {
        pub fn from_file<P: AsRef<Path>>(path: P) -> Result<LoadedFlash> {
            Ok(LoadedFlash {
                data: std::fs::read(path)?,
            })
        }
    }

    impl ReadStorage for LoadedFlash {
        type Error = FlashError;

        fn capacity(&self) -> usize {
            // TODO: The flash would be larger than this, but this works for now.
            self.data.len()
        }

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> FlashResult<()> {
            if offset as usize + bytes.len() <= self.data.len() {
                bytes.clone_from_slice(&self.data[offset as usize .. offset as usize + bytes.len()]);
                Ok(())
            } else {
                Err(FlashError::ReadBound)
            }
        }
    }
}
