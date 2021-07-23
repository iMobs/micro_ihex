use crate::checksum::checksum;
use crate::IHex;

impl IHex {
    pub fn serialize<T>(&self, buffer: &mut T) -> Result<usize, ()>
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
}

fn format<T>(record_type: u8, offset: u16, data: &[u8], buffer: &mut T) -> Result<usize, ()>
where
    T: AsMut<[u8]>,
{
    let buffer = buffer.as_mut();
    let data_length = 1 + 2 + 1 + data.len() + 1;

    let buffer_length = 2 * data_length + 1;
    if buffer.len() < buffer_length {
        // Freak out
    }

    let mut bytes = [0; 0x200];
    bytes[0] = data.len() as u8;
    bytes[1..3].copy_from_slice(&offset.to_be_bytes());
    bytes[3] = record_type;
    bytes[4..data_length - 1].copy_from_slice(data);
    let checksum = checksum(&bytes[..data_length - 1]);
    bytes[data_length - 1] = checksum;

    buffer[0] = b':';

    if hex::encode_to_slice(&bytes[..data_length], &mut buffer[1..buffer_length]).is_err() {
        // Freak out
    }

    Ok(buffer_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_data() {
        let expected = [
            0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x67, 0x61, 0x70,
        ];

        let mut bytes = [0; 0xFF];
        bytes[..expected.len()].copy_from_slice(&expected);

        let record = IHex::Data {
            bytes,
            length: expected.len() as u8,
            offset: 0x0010,
        };

        let mut buffer = [0; 0x200];
        let length = record.serialize(&mut buffer).unwrap();

        assert_eq!(&buffer[..length], b":0b0010006164647265737320676170a7");
    }

    #[test]
    fn serialize_eof() {
        let record = IHex::EndOfFile;

        let mut buffer = [0; 0x200];
        let length = record.serialize(&mut buffer).unwrap();

        assert_eq!(&buffer[..length], b":00000001ff");
    }

    #[test]
    fn serialize_extended_segment_address() {
        let record = IHex::ExtendedSegmentAddress(0x12FE);

        let mut buffer = [0; 0x200];
        let length = record.serialize(&mut buffer).unwrap();

        assert_eq!(&buffer[..length], b":0200000212feec");
    }

    #[test]
    fn serialize_start_segment_address() {
        let record = IHex::StartSegmentAddress {
            cs: 0x1234,
            ip: 0x3800,
        };

        let mut buffer = [0; 0x200];
        let length = record.serialize(&mut buffer).unwrap();

        assert_eq!(&buffer[..length], b":04000003123438007b");
    }

    #[test]
    fn serialize_extended_linear_address() {
        let record = IHex::ExtendedLinearAddress(0xABCD);

        let mut buffer = [0; 0x200];
        let length = record.serialize(&mut buffer).unwrap();

        assert_eq!(&buffer[..length], b":02000004abcd82");
    }

    #[test]
    fn serialize_start_linear_address() {
        let record = IHex::StartLinearAddress(0x12345678);

        let mut buffer = [0; 0x200];
        let length = record.serialize(&mut buffer).unwrap();

        assert_eq!(&buffer[..length], b":0400000512345678e3");
    }
}
