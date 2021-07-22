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
			Self::Data { .. } => types::DATA,
			Self::EndOfFile => types::END_OF_FILE,
			Self::ExtendedSegmentAddress(_) => types::EXTENDED_SEGMENT_ADDRESS,
			Self::StartSegmentAddress { .. } => types::START_SEGMENT_ADDRESS,
			Self::ExtendedLinearAddress(_) => types::EXTENDED_LINEAR_ADDRESS,
			Self::StartLinearAddress(_) => types::START_LINEAR_ADDRESS,
		}
	}
}
