use crate::types;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Debug, PartialEq)]
pub enum IHex {
    Data {
        #[cfg(feature = "alloc")]
        bytes: Vec<u8>,
        #[cfg(not(feature = "alloc"))]
        bytes: [u8; 0xFF],
        length: u8,
        offset: u16,
    },
    EndOfFile,
    ExtendedSegmentAddress(u16),
    StartSegmentAddress {
        cs: u16,
        ip: u16,
    },
    ExtendedLinearAddress(u16),
    StartLinearAddress(u32),
}

impl IHex {
    pub fn record_type(&self) -> u8 {
        match self {
            Self::Data { .. } => types::DATA,
            Self::EndOfFile => types::END_OF_FILE,
            Self::ExtendedSegmentAddress(_) => types::EXTENDED_SEGMENT_ADDRESS,
            Self::StartSegmentAddress { .. } => types::START_SEGMENT_ADDRESS,
            Self::ExtendedLinearAddress(_) => types::EXTENDED_LINEAR_ADDRESS,
            Self::StartLinearAddress(_) => types::START_LINEAR_ADDRESS,
        }
    }
}
