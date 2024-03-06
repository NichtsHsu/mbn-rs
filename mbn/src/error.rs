/// Re-export [`std::io::Error`].
pub use std::io::Error as IOError;

/// Re-export [`elf::ParseError`].
pub use elf::ParseError as ElfError;

/// The error type for parsing MBN format file.
#[derive(Debug)]
pub enum ParseError {
    /// Length of hash table is not a multiple of 32 or 48,
    /// or hash table does not contain at least 2 entries.
    HashTableNotAligned(u32),
    /// Input buffer length may be not long enough.
    InputUnexpectedTermination,
    /// File or byte stream format is invalid.
    InvalidFormat(ElfError),
    /// Input value is invalid.
    InvalidValue,
    /// I/O Error.
    IO(IOError),
    /// Length of metadata is not 120.
    MetadataNotAligned(u32),
    /// Cannot find hash table segment.
    NoHashTableSegment,
    /// MBN header version is not supported.
    UnsupportedHeaderVersion(u32),
    /// MBN image ID is not supported.
    UnsupportedImageId(u32),
}

impl From<std::io::Error> for ParseError {
    fn from(value: std::io::Error) -> Self {
        ParseError::IO(value)
    }
}

impl From<elf::ParseError> for ParseError {
    fn from(value: elf::ParseError) -> Self {
        ParseError::InvalidFormat(value)
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::HashTableNotAligned(len) => {
                write!(
                    f,
                    "Length of hash table '{}' is not a multiple of 32 or 48, \
                        or hash table does not contain at least 2 entries.",
                    len
                )
            }
            ParseError::InputUnexpectedTermination => {
                write!(f, "Input buffer length may be not long enough")
            }
            ParseError::InvalidFormat(error) => write!(f, "{}", error),
            ParseError::InvalidValue => write!(f, "Input value is invalid"),
            ParseError::IO(error) => write!(f, "{}", error),
            ParseError::MetadataNotAligned(len) => {
                write!(f, "Length of metadata '{}' is not 120", len)
            }
            ParseError::NoHashTableSegment => write!(f, "Cannot find hash table segment"),
            ParseError::UnsupportedHeaderVersion(version) => {
                write!(f, "MBN header version '{}' is not supported", version)
            }
            ParseError::UnsupportedImageId(id) => {
                write!(f, "MBN image ID '{}' is not supported", id)
            }
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::InvalidFormat(error) => Some(error),
            ParseError::IO(error) => Some(error),
            _ => None,
        }
    }
}
