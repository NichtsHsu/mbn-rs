//! MBN format parsing library.
//!
//! **NOTE**: Extension of files with MBN segment may be `elf`.
//! Files with extension `mbn` are almost ELF format files.
//!
//! Parse from an ELF format file, see [`from_elf()`].
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

use std::path::Path;

pub use hash_table_segment::*;
pub use header::*;
pub use metadata::*;

pub(crate) type Result<T> = std::result::Result<T, error::ParseError>;

use elf::abi::PT_NULL;
use elf::endian::AnyEndian;
use elf::segment::ProgramHeader;
use elf::ElfBytes;

/// Parse hash table segment from an ELF format binaries.
pub fn from_elf<P: AsRef<Path>>(path: P) -> Result<HashTableSegment> {
    pub use error::ParseError;
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
