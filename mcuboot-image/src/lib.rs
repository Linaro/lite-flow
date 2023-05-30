#![feature(maybe_uninit_as_bytes)]

use core::slice;
use embedded_storage::ReadStorage;
use std::{
    mem::{self, size_of, MaybeUninit},
    path::Path,
};
use thiserror::Error;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[derive(Error, Debug)]
pub enum Error {
    // TODO: Capture flash errors, but they are overly generic, and we can't get
    // any information out of them, so just drop the error.
    #[error("Flash operation error")]
    Flash,

    // For development, capture io errors, even though we will want to this to
    // become nostd at some point.
    #[error("io error")]
    Io(#[from] std::io::Error),

    // Something is wrong with the TLV
    #[error("Invalid TLV entry")]
    InvalidTlv,
}

type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {

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

        // let head: Header = AsRaw::from_bytes(&image[0..32]);
        let head: Header = image.from_storage(0).unwrap();
        println!("Imagec: {:#x?}", head);
        println!("TLV: {:x?}", head.tlv_base());
        let _ = Tlv::new(&head, &mut image);
        panic!("TODO");
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Header {
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
pub struct Version {
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
trait AsRaw: Sized {
    fn as_raw(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<Self>()) }
    }

    fn as_raw_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self as *mut _ as *mut u8, mem::size_of::<Self>()) }
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

impl<T: ReadStorage> ReadStorageExt for T {
    fn from_storage<R: AsRaw>(&mut self, offset: u32) -> Result<R> {
        // TODO: Some experimental features of the compiler may allow this
        // to be done as an array with const, but for now, just alloc.
        // let mut buf = [0u8; size_of::<R>()];
        let mut buf = vec![0u8; size_of::<R>()];
        self.read(offset, &mut buf).map_err(|_| Error::Flash)?;
        Ok(AsRaw::from_bytes(&buf))
    }
}

/// Tracker for the TLV.  The slice are the raw bytes of the TLV.
pub struct Tlv {
    // protect_size: usize,
}

/// There are two forms of the TLV. When there is a protected TLV, there is
/// a protected header, followed by the given number of bytes of protected
/// entries. This is then followed by an unprotected header, which will have
/// some number of entries following it.
/// In each case, the header length includes the header itself.
impl Tlv {
    pub fn new<FF: ReadStorage>(head: &Header, flash: &mut FF) -> Result<Tlv> {
        let base = head.tlv_base();
        let tlv_head: TlvHead = flash.from_storage(head.tlv_base() as u32)?;
        println!("Head: {:#x?}", tlv_head);

        match tlv_head.tag {
            0x6907 => unimplemented!(),
            0x6908 => {
                // This is a protected TLV.  The TLV size must match the protected size in the header.
                if head.protect_tlv_size == 0 || head.protect_tlv_size != tlv_head.length {
                    return Err(Error::InvalidTlv);
                }

                // There should be an unprotected header after this many bytes.
                let unprot_offset = head.tlv_base() + tlv_head.length as usize;
                let unprot_head: TlvHead = flash.from_storage(unprot_offset as u32)?;
                println!("unprot {:#x?}", unprot_head);

                // Walk through the protected TLV.
                let mut offset = size_of::<TlvHead>();
                while offset < tlv_head.length as usize {
                    let tag: TlvTag = flash.from_storage((head.tlv_base() + offset) as u32)?;
                    println!("prot {:x} {:#x?}", offset, tag);
                    offset += size_of::<TlvTag>() + tag.length as usize;
                }
                println!("Prot done");

                let base = head.tlv_base() + tlv_head.length as usize;
                offset = size_of::<TlvHead>();
                while offset < unprot_head.length as usize {
                    let tag: TlvTag = flash.from_storage((base + offset) as u32)?;
                    println!("unprot {:x} {:#x?}", offset, tag);
                    offset += size_of::<TlvTag>() + tag.length as usize;
                }
                println!("Unprot done");
            }
            _ => return Err(Error::InvalidTlv),
        }
        Ok(Tlv {})
    }
}

#[repr(C)]
#[derive(Debug)]
struct TlvHead {
    tag: u16,
    length: u16,
}
impl AsRaw for TlvHead {}

#[repr(C)]
#[derive(Debug)]
struct TlvTag {
    kind: u16,
    length: u16,
}
impl AsRaw for TlvTag {}

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
            bytes.clone_from_slice(&self.data[offset as usize..offset as usize + bytes.len()]);
            Ok(())
        } else {
            Err(FlashError::ReadBound)
        }
    }
}
