use crate::types;

#[derive(Debug, PartialEq)]
pub enum IHex {
    Data {
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
            IHex::Data { .. } => types::DATA,
            IHex::EndOfFile => types::END_OF_FILE,
            IHex::ExtendedSegmentAddress(_) => types::EXTENDED_SEGMENT_ADDRESS,
            IHex::StartSegmentAddress { .. } => types::START_SEGMENT_ADDRESS,
            IHex::ExtendedLinearAddress(_) => types::EXTENDED_LINEAR_ADDRESS,
            IHex::StartLinearAddress(_) => types::START_LINEAR_ADDRESS,
        }
    }
}
