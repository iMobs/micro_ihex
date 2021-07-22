use crate::checksum::checksum;
use crate::types;
use crate::{IHex, IHexError};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

impl IHex {
    #[cfg(feature = "alloc")]
    pub fn parse_multi<'a>(
        string: &'a str,
    ) -> Box<dyn Iterator<Item = Result<IHex, IHexError>> + 'a> {
        let lines = string.lines().map(Self::parse);

        Box::new(lines)
    }

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

        let checksum = checksum(bytes);

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    use alloc::{string::String, vec, vec::Vec};

    #[test]
    #[cfg(feature = "alloc")]
    fn parse_string() {
        let data = String::from(":00000001FF");
        assert_eq!(IHex::parse(data), Ok(IHex::EndOfFile));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn parse_vec() {
        let data = String::from(":00000001FF").into_bytes();
        assert_eq!(IHex::parse(data), Ok(IHex::EndOfFile));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn parse_multi() {
        let string = String::from(":0200000212FEEC\r\n:00000001FF\r\n");
        let result = IHex::parse_multi(&string)
            .collect::<Result<Vec<IHex>, IHexError>>()
            .unwrap();

        assert_eq!(
            result,
            vec![IHex::ExtendedSegmentAddress(0x12FE), IHex::EndOfFile]
        )
    }

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
