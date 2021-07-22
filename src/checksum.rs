pub(crate) fn checksum(bytes: &[u8]) -> u8 {
	0u8.wrapping_sub(bytes.iter().fold(0u8, |acc, &byte| acc.wrapping_add(byte)))
}
