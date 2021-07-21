#![no_std]

#[derive(Debug, PartialEq)]
pub enum IHexError {
    MissingColon,
    ParseError,
    BadChecksum(u8, u8),
    BadLength,
    BadType,
}

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

pub mod types {
    pub const DATA: u8 = 0x00;
    pub const END_OF_FILE: u8 = 0x01;
    pub const EXTENDED_SEGMENT_ADDRESS: u8 = 0x02;
    pub const START_SEGMENT_ADDRESS: u8 = 0x03;
    pub const EXTENDED_LINEAR_ADDRESS: u8 = 0x04;
    pub const START_LINEAR_ADDRESS: u8 = 0x05;
}

impl IHex {
    pub fn parse<T>(line: T) -> Result<IHex, IHexError>
    where
        T: AsRef<[u8]>,
    {
        let line = line.as_ref();

        if line[0] != b':' {
            return Err(IHexError::MissingColon);
        }

        let line = &line[1..];

        let mut bytes = [0; 0x200];

        let length = line.len() / 2;

        if hex::decode_to_slice(line, &mut bytes[..length]).is_err() {
            return Err(IHexError::ParseError);
        }

        let expected_checksum = bytes[length - 1];
        let bytes = &bytes[..length - 1];

        let checksum = 0u8.wrapping_sub(checksum(bytes));

        if checksum != expected_checksum {
            return Err(IHexError::BadChecksum(checksum, expected_checksum));
        }

        let length = bytes[0];

        let mut short = [0; 2];

        short.clone_from_slice(&bytes[1..3]);
        let address = u16::from_be_bytes(short);

        let record_type = bytes[3];
        let data = &bytes[4..];

        if data.len() != length as usize {
            return Err(IHexError::BadLength);
        }

        match record_type {
            types::DATA => {
                let mut bytes = [0; 0xFF];

                bytes[..data.len()].clone_from_slice(data);

                Ok(IHex::Data {
                    bytes,
                    length,
                    offset: address,
                })
            }
            types::END_OF_FILE => Ok(IHex::EndOfFile),
            types::EXTENDED_SEGMENT_ADDRESS => {
                let mut short = [0; 2];

                short.clone_from_slice(&data[0..2]);
                let address = u16::from_be_bytes(short);

                Ok(IHex::ExtendedSegmentAddress(address))
            }
            types::START_SEGMENT_ADDRESS => {
                let mut short = [0; 2];

                short.clone_from_slice(&data[0..2]);
                let cs = u16::from_be_bytes(short);

                short.clone_from_slice(&data[2..4]);
                let ip = u16::from_be_bytes(short);

                Ok(IHex::StartSegmentAddress { cs, ip })
            }
            types::EXTENDED_LINEAR_ADDRESS => {
                let mut short = [0; 2];

                short.clone_from_slice(&data[0..2]);
                let ela = u16::from_be_bytes(short);

                Ok(IHex::ExtendedLinearAddress(ela))
            }
            types::START_LINEAR_ADDRESS => {
                let mut word = [0; 4];

                word.clone_from_slice(&data[0..4]);
                let sla = u32::from_be_bytes(word);

                Ok(IHex::StartLinearAddress(sla))
            }
            _ => Err(IHexError::BadType),
        }
    }

    pub fn serialize<T>(&self, buffer: &mut T)
    where
        T: AsMut<[u8]>,
    {
        let record_type = self.record_type();

        match self {
            Self::Data {
                bytes,
                length,
                offset,
            } => format(record_type, *offset, &bytes[..*length as usize], buffer),
            Self::EndOfFile => format(record_type, 0, &[], buffer),
            Self::ExtendedSegmentAddress(address) => {
                format(record_type, 0, &address.to_be_bytes(), buffer)
            }
            Self::StartSegmentAddress { cs, ip } => {
                let mut word = [0; 4];
                word[..2].copy_from_slice(&cs.to_be_bytes());
                word[2..].copy_from_slice(&ip.to_be_bytes());

                format(record_type, 0, &word, buffer)
            }
            Self::ExtendedLinearAddress(address) => {
                format(record_type, 0, &address.to_be_bytes(), buffer)
            }
            Self::StartLinearAddress(address) => {
                format(record_type, 0, &address.to_be_bytes(), buffer)
            }
        }
    }

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

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &byte| acc.wrapping_add(byte))
}

fn format<T>(record_type: u8, offset: u16, data: &[u8], buffer: &mut T)
where
    T: AsMut<[u8]>,
{
    let buffer = buffer.as_mut();
    let mut bytes = [0; 0x200];
    let data_length = 1 + 2 + 1 + data.len() + 1;

    let buffer_length = 2 * data_length + 1;
    if buffer.len() < buffer_length {
        // Freak out
    }

    bytes[0] = data.len() as u8;
    bytes[1..3].copy_from_slice(&offset.to_be_bytes());
    bytes[3] = record_type;
    bytes[4..data_length - 1].copy_from_slice(data);
    bytes[data_length - 1] = checksum(&bytes[..data_length - 1]);

    buffer[0] = b':';

    if hex::encode_to_slice(&bytes[..data_length], &mut buffer[1..buffer_length]).is_err() {
        // Freak out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_data() {
        let expected = [
            0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x67, 0x61, 0x70,
        ];

        let mut bytes = [0; 0xFF];
        bytes[..expected.len()].clone_from_slice(&expected);

        assert_eq!(
            IHex::parse(":0B0010006164647265737320676170A7"),
            Ok(IHex::Data {
                bytes,
                length: expected.len() as u8,
                offset: 0x0010,
            })
        );
    }

    #[test]
    fn parse_eof() {
        assert_eq!(IHex::parse(":00000001FF"), Ok(IHex::EndOfFile));
    }

    #[test]
    fn parse_extended_segment_address() {
        assert_eq!(
            IHex::parse(":0200000212FEEC"),
            Ok(IHex::ExtendedSegmentAddress(0x12FE))
        );
    }

    #[test]
    fn parse_start_segment_address() {
        assert_eq!(
            IHex::parse(":04000003123438007B"),
            Ok(IHex::StartSegmentAddress {
                cs: 0x1234,
                ip: 0x3800
            })
        );
    }

    #[test]
    fn parse_extended_linear_address() {
        assert_eq!(
            IHex::parse(":02000004ABCD82"),
            Ok(IHex::ExtendedLinearAddress(0xABCD))
        );
    }

    #[test]
    fn parse_start_linear_address() {
        assert_eq!(
            IHex::parse(":0400000512345678E3"),
            Ok(IHex::StartLinearAddress(0x12345678))
        );
    }
}
