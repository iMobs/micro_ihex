#![no_std]

use hex;

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

impl IHex {
    pub fn parse(line: &str) -> Result<IHex, IHexError> {
        if let Some(':') = line.chars().next() {
            // Do nothing
        } else {
            return Err(IHexError::MissingColon);
        }

        let line = &line[1..];

        let mut bytes = [0; 0x110];

        let length = line.len() / 2;

        if let Err(_) = hex::decode_to_slice(line, &mut bytes[..length]) {
            return Err(IHexError::ParseError);
        }

        let expected_checksum = bytes[length - 1];
        let bytes = &bytes[..length - 1];

        let checksum =
            0u8.wrapping_sub(bytes.iter().fold(0u8, |acc, &byte| acc.wrapping_add(byte)));

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

        // TODO: Replace with constants
        match record_type {
            0 => {
                let mut bytes = [0; 0xFF];

                bytes[..data.len()].clone_from_slice(data);

                Ok(IHex::Data {
                    bytes,
                    length,
                    offset: address,
                })
            }
            1 => Ok(IHex::EndOfFile),
            2 => {
                let mut short = [0; 2];

                short.clone_from_slice(&data[0..2]);
                let address = u16::from_be_bytes(short);

                Ok(IHex::ExtendedSegmentAddress(address))
            }
            3 => {
                let mut short = [0; 2];

                short.clone_from_slice(&data[0..2]);
                let cs = u16::from_be_bytes(short);

                short.clone_from_slice(&data[2..4]);
                let ip = u16::from_be_bytes(short);

                Ok(IHex::StartSegmentAddress { cs, ip })
            }
            4 => {
                let mut short = [0; 2];

                short.clone_from_slice(&data[0..2]);
                let ela = u16::from_be_bytes(short);

                Ok(IHex::ExtendedLinearAddress(ela))
            }
            5 => {
                let mut word = [0; 4];

                word.clone_from_slice(&data[0..4]);
                let sla = u32::from_be_bytes(word);

                Ok(IHex::StartLinearAddress(sla))
            }
            _ => Err(IHexError::BadType),
        }
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
