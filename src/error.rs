#[derive(Debug, PartialEq)]
pub enum IHexError {
	MissingColon,
	ParseError,
	BadChecksum(u8, u8),
	BadLength,
	BadType,
}
