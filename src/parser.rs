use crate::checksum::checksum;
use crate::types;
use crate::IHex;
use core::iter::FusedIterator;
use core::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum ParseError {
    MissingColon,
    ParseError,
    BadChecksum(u8, u8),
    BadLength,
    BadType,
}

type ParseResult = Result<IHex, ParseError>;

impl IHex {
    pub fn parse<T: AsRef<[u8]>>(line: T) -> ParseResult {
        let line = line.as_ref();

        if line[0] != b':' {
            return Err(ParseError::MissingColon);
        }

        let line = &line[1..];

        let mut bytes = [0; 0x200];

        let length = line.len() / 2;

        if hex::decode_to_slice(line, &mut bytes[..length]).is_err() {
            return Err(ParseError::ParseError);
        }

        let expected_checksum = bytes[length - 1];
        let bytes = &bytes[..length - 1];

        let checksum = checksum(bytes);

        if checksum != expected_checksum {
            return Err(ParseError::BadChecksum(checksum, expected_checksum));
        }

        let length = bytes[0];

        let mut short = [0; 2];

        short.clone_from_slice(&bytes[1..3]);
        let address = u16::from_be_bytes(short);

        let record_type = bytes[3];
        let data = &bytes[4..];

        if data.len() != length as usize {
            return Err(ParseError::BadLength);
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
            _ => Err(ParseError::BadType),
        }
    }
}

impl FromStr for IHex {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IHex::parse(s)
    }
}

pub struct Parser<'a> {
    inner: core::str::Lines<'a>,
    done: bool,
}

impl<'a> Parser<'a> {
    pub fn new(s: &'a str) -> Self {
        Parser {
            inner: s.lines(),
            done: false,
        }
    }

    fn next_line(&mut self) -> Option<&'a str> {
        for line in &mut self.inner {
            if !line.is_empty() {
                return Some(line);
            }
        }

        None
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = ParseResult;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        self.next_line().map(IHex::parse)
    }
}

impl<'a> FusedIterator for Parser<'a> {}

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
        let data = IHex::Data {
            bytes,
            length: expected.len() as u8,
            offset: 0x0010,
        };

        assert_eq!(":0B0010006164647265737320676170A7".parse(), Ok(data));
    }

    #[test]
    fn parse_eof() {
        let eof = IHex::EndOfFile;

        assert_eq!(":00000001FF".parse(), Ok(eof));
    }

    #[test]
    fn parse_extended_segment_address() {
        let esa = IHex::ExtendedSegmentAddress(0x12FE);

        assert_eq!(":0200000212FEEC".parse(), Ok(esa));
    }

    #[test]
    fn parse_start_segment_address() {
        let ssa = IHex::StartSegmentAddress {
            cs: 0x1234,
            ip: 0x3800,
        };

        assert_eq!(":04000003123438007B".parse(), Ok(ssa));
    }

    #[test]
    fn parse_extended_linear_address() {
        let ela = IHex::ExtendedLinearAddress(0xABCD);

        assert_eq!(":02000004ABCD82".parse(), Ok(ela));
    }

    #[test]
    fn parse_start_linear_address() {
        let sla = IHex::StartLinearAddress(0x12345678);

        assert_eq!(":0400000512345678E3".parse(), Ok(sla));
    }

    #[test]
    fn multi_line_parser() {
        let ela = IHex::ExtendedLinearAddress(0xABCD);
        let sla = IHex::StartLinearAddress(0x12345678);

        let mut parser = Parser::new(":02000004ABCD82\r\n\r\n:0400000512345678E3\r\n");

        assert_eq!(parser.next(), Some(Ok(ela)));
        assert_eq!(parser.next(), Some(Ok(sla)));
        assert_eq!(parser.next(), None)
    }
}
