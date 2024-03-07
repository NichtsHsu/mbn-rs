//! MBN format parsing library.
//!
//! Parse from an ELF file (files with `.mbn` extension are usually ELF file), see [`from_elf()`].
//!
//! Parse from byte stream, see [`HashTableSegment::parse()`].
//!
//! Dump to byte stream, see [`HashTableSegment::dump()`].

#![allow(clippy::len_without_is_empty)]

pub(crate) mod byte_read;

/// Define error types.
pub mod error;

mod hash_table_segment;
mod header;
mod metadata;

pub use hash_table_segment::*;
pub use header::*;
pub use metadata::*;

pub(crate) type Result<T> = std::result::Result<T, error::ParseError>;

use elf::abi::PT_NULL;
use elf::endian::AnyEndian;
use elf::segment::ProgramHeader;
use elf::ElfBytes;

/// Parse hash table segment from an ELF format binaries.
pub fn from_elf(path: &str) -> Result<HashTableSegment> {
    pub use error::ParseError;
    let path = std::path::PathBuf::from(path);
    let file_data = std::fs::read(path)?;
    let file = ElfBytes::<AnyEndian>::minimal_parse(file_data.as_slice())?;
    let all_null_phdrs: Vec<ProgramHeader> = file
        .segments()
        .ok_or(ParseError::NoHashTableSegment)?
        .iter()
        .filter(|phdr| phdr.p_type == PT_NULL)
        .collect();
    let hash_table_segment = all_null_phdrs
        .get(1)
        .ok_or(ParseError::NoHashTableSegment)?;
    let hash_table_segment = file.segment_data(hash_table_segment)?;
    HashTableSegment::parse(hash_table_segment)
}
