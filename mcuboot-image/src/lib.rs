#![feature(maybe_uninit_as_bytes)]

use embedded_storage::ReadStorage;
use num_enum::TryFromPrimitive;
use std::{
    mem::size_of,
    path::Path,
};
use thiserror::Error;

use mcuboot_direct::{AsRaw, ReadStorageExt};

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

/// Storage doesn't constrain it's error type, so it is awkward to use. This
/// macro will try a storage operation, mapping the error return to the above
/// `Storage` error.
macro_rules! try_storage {
    ($e:expr) => {
        $e.map_err(|_| Error::Flash)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let tlv = Tlv::new(&head, &mut image).unwrap();
        println!("TLV: {:#x?}", tlv);
        tlv.validate(&mut image).unwrap();
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

/// Tracker for the TLV.  The slice are the raw bytes of the TLV.
#[derive(Debug)]
pub struct Tlv {
    protect: Option<TlvSection>,
    unprotect: TlvSection,
}

/// Represents a single TLV block, with a header, and some number of bytes of data after it.
#[derive(Debug)]
struct TlvSection {
    offset: usize,
    header: TlvHead,
}

/// Magic numbers for the TLV headers.
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum TlvMagic {
    InfoMagic = 0x6907,
    ProtInfoMagic = 0x6908,
}

/// Known tags for the TLV tags.
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum TlvTag {
    KeyHash = 0x01,
    PubKey = 0x02,
    Sha256 = 0x10,
    Rsa2048Pss = 0x20,
    Ecdsa224 = 0x21,
    Ecdsa256 = 0x22,
    Rsa3072Pss = 0x23,
    Ed25519 = 0x24,
    EncRsa2048 = 0x30,
    EncKw = 0x31,
    EncEc256 = 0x32,
    EncX25519 = 0x33,
    Dependency = 0x40,
    SecCnt = 0x50,
    BootRecord = 0x60,
}

/// There are two forms of the TLV. When there is a protected TLV, there is
/// a protected header, followed by the given number of bytes of protected
/// entries. This is then followed by an unprotected header, which will have
/// some number of entries following it.
/// In each case, the header length includes the header itself.
impl Tlv {
    pub fn new<FF: ReadStorage>(head: &Header, flash: &mut FF) -> Result<Tlv> {
        let base = head.tlv_base();
        let tlv_head: TlvHead = try_storage!(flash.from_storage(head.tlv_base() as u32))?;

        match tlv_head.tag.try_into() {
            Ok(TlvMagic::ProtInfoMagic) => {
            // 0x6907 => {
                // There isn't anything to test about the TLV at this point. A
                // validate will make sure that all of the sections can be read.
                Ok(Tlv {
                    protect: None,
                    unprotect: TlvSection {
                        offset: base,
                        header: tlv_head,
                    }
                })
            }
            Ok(TlvMagic::InfoMagic) => {
            // 0x6908 => {
                // This is a protected TLV.  The TLV size must match the protected size in the header.
                if head.protect_tlv_size == 0 || head.protect_tlv_size != tlv_head.length {
                    return Err(Error::InvalidTlv);
                }

                // There should be an unprotected header after this many bytes.
                let unprot_offset = head.tlv_base() + tlv_head.length as usize;
                let unprot_head: TlvHead = try_storage!(flash.from_storage(unprot_offset as u32))?;

                Ok(Tlv {
                    protect: Some(TlvSection {
                        offset: base,
                        header: tlv_head,
                    }),
                    unprotect: TlvSection {
                        offset: unprot_offset,
                        header: unprot_head,
                    }
                })
            }
            _ => return Err(Error::InvalidTlv),
        }
    }

    /// Validate that the TLV sections can be iterated, and that everything is
    /// in the proper section.
    pub fn validate<FF: ReadStorage>(&self, flash: &mut FF) -> Result<()> {
        if let Some(ref prot) = self.protect {
            Self::walk(prot, flash)?
        }
        Self::walk(&self.unprotect, flash)?;
        Ok(())
    }

    /// Attempt to walk through the given TLV section, returning Ok(()) if all
    /// of the TLV tags can be read. Will also return an error if the walk goes
    /// past the end of the flash.
    fn walk<FF: ReadStorage>(section: &TlvSection, flash: &mut FF) -> Result<()> {
        let nbase = section.offset;
        let mut offset = size_of::<TlvHead>();
        while offset < section.header.length as usize {
            // TODO: Arith overflow here.
            let tag: TlvItem = try_storage!(flash.from_storage((nbase + offset) as u32))?;
            println!("tag: {:x} {:x?}", offset, tag);
            offset += size_of::<TlvTag>() + tag.length as usize;

            // Make sure we are always within the bounds of the flash.
            if (nbase + offset) > flash.capacity() {
                return Err(Error::InvalidTlv);
            }
        }
        Ok(())
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
struct TlvItem {
    kind: u16,
    length: u16,
}
impl AsRaw for TlvItem {}

#[derive(Error, Debug)]
pub enum FlashError {
    #[error("Read past device bounds")]
    ReadBound,
}
type FlashResult<T> = std::result::Result<T, FlashError>;

/// A simulated flash device loaded from an image.
pub struct LoadedFlash {
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
