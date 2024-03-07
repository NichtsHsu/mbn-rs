use crate::{byte_read::ByteReader, error::ParseError, MbnHeader, MbnHeaderV6, Metadata, Result};

/// Trailing padding of [`HashTableSegment`].
#[derive(Clone, Copy, Debug)]
pub struct Padding {
    /// Byte used for padding, typically `0xFF`.
    pub content: u8,
    /// Length of padding in bytes.
    pub len: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum HashEntry {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
}

/// Hash table segment representation.
#[derive(Clone, Debug)]
pub struct HashTableSegment {
    /// MBN header, including locations of fields inside hash segment.
    pub mbn_header: MbnHeader,
    /// Information about the image supplied by QTI.
    pub qti_metadata: Option<Metadata>,
    /// Information about the image supplied by OEM.
    pub metadata: Option<Metadata>,
    /// Hashes of other segments in the ELF file.
    pub hash_table: Vec<HashEntry>,
    /// QTI signature.
    pub qti_signature: Vec<u8>,
    /// QTI certificate chain.
    pub qti_certificate_chain: Vec<u8>,
    /// OEM signature.
    pub signature: Vec<u8>,
    /// OEM certificate chain.
    pub certificate_chain: Vec<u8>,
    /// Padding bytes.
    pub padding: Padding,
}

impl HashEntry {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            HashEntry::Sha1(entry) => entry,
            HashEntry::Sha256(entry) => entry,
            HashEntry::Sha384(entry) => entry,
        }
    }
}

impl HashTableSegment {
    /// Parse byte stream to hash table segment.
    ///
    /// NOTE: The unparsed parts at the end of byte stream are considered padding.
    ///
    /// Hint: Many `*.mbn` files are actually ELF files, please parse them via [`from_elf()`](crate::from_elf())
    /// instead of this function.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(raw);

        let mbn_header = reader.read()?;

        let qti_metadata = match &mbn_header {
            MbnHeader::V6(
                header @ MbnHeaderV6 {
                    qti_metadata_size: 1..,
                    ..
                },
            ) => {
                if header.qti_metadata_size != 120 {
                    return Err(ParseError::MetadataNotAligned(header.qti_metadata_size));
                }
                Some(reader.read()?)
            }
            _ => None,
        };

        let metadata = match &mbn_header {
            MbnHeader::V6(
                header @ MbnHeaderV6 {
                    metadata_size: 1.., ..
                },
            ) => {
                if header.metadata_size != 120 {
                    return Err(ParseError::MetadataNotAligned(header.qti_metadata_size));
                }
                Some(reader.read()?)
            }
            _ => None,
        };

        let mut hash_table = vec![];
        let code_size = match &mbn_header {
            MbnHeader::V3Len40(header) => header.code_size,
            MbnHeader::V3Len80(header) => header.code_size,
            MbnHeader::V5(header) => header.code_size,
            MbnHeader::V6(header) => header.code_size,
        };
        let sha_algo = if let MbnHeader::V6(_) = &mbn_header {
            "SHA384"
        } else {
            let maybe_dummy = reader.peek::<[u8; 20]>(20)?;
            if maybe_dummy.iter().all(|x| *x == 0) {
                "SHA1"
            } else {
                let maybe_dummy = reader.peek::<[u8; 32]>(32)?;
                if maybe_dummy.iter().all(|x| *x == 0) {
                    "SHA256"
                } else {
                    return Err(ParseError::HashTableNotAligned(code_size));
                }
            }
        };
        match sha_algo {
            "SHA1" => {
                if code_size % 20 != 0 {
                    return Err(ParseError::HashTableNotAligned(code_size));
                }
                for _ in 0..code_size / 20 {
                    hash_table.push(HashEntry::Sha1(reader.read()?));
                }
            }
            "SHA256" => {
                if code_size % 32 != 0 {
                    return Err(ParseError::HashTableNotAligned(code_size));
                }
                for _ in 0..code_size / 32 {
                    hash_table.push(HashEntry::Sha256(reader.read()?));
                }
            }
            "SHA384" => {
                if code_size % 48 != 0 {
                    return Err(ParseError::HashTableNotAligned(code_size));
                }
                for _ in 0..code_size / 48 {
                    hash_table.push(HashEntry::Sha384(reader.read()?));
                }
            }
            _ => unreachable!(),
        };

        let qti_signature = match &mbn_header {
            MbnHeader::V5(header) => reader.skip(header.qti_signature_size as usize)?,
            MbnHeader::V6(header) => reader.skip(header.qti_signature_size as usize)?,
            _ => vec![],
        };

        let qti_certificate_chain = match &mbn_header {
            MbnHeader::V5(header) => reader.skip(header.qti_cert_chain_size as usize)?,
            MbnHeader::V6(header) => reader.skip(header.qti_cert_chain_size as usize)?,
            _ => vec![],
        };

        let signature = match &mbn_header {
            MbnHeader::V3Len40(header) => reader.skip(header.signature_size as usize)?,
            MbnHeader::V3Len80(header) => reader.skip(header.signature_size as usize)?,
            MbnHeader::V5(header) => reader.skip(header.signature_size as usize)?,
            MbnHeader::V6(header) => reader.skip(header.signature_size as usize)?,
        };

        let certificate_chain = match &mbn_header {
            MbnHeader::V3Len40(header) => reader.skip(header.cert_chain_size as usize)?,
            MbnHeader::V3Len80(header) => reader.skip(header.cert_chain_size as usize)?,
            MbnHeader::V5(header) => reader.skip(header.cert_chain_size as usize)?,
            MbnHeader::V6(header) => reader.skip(header.cert_chain_size as usize)?,
        };

        let mut padding = Padding {
            content: 0xFF,
            len: reader.available(),
        };
        if padding.len > 0 {
            padding.content = reader.read()?;
        }

        Ok(Self {
            mbn_header,
            qti_metadata,
            metadata,
            hash_table,
            qti_signature,
            qti_certificate_chain,
            signature,
            certificate_chain,
            padding,
        })
    }

    /// Dump hash table segment to byte stream.
    ///
    /// * `padding`: Write padding to byte stream or not.
    pub fn dump<W: std::io::Write>(&self, writer: &mut W, padding: bool) -> Result<()> {
        writer.write_all(self.mbn_header.as_bytes())?;
        if let Some(metadata) = &self.qti_metadata {
            writer.write(metadata.as_bytes())?;
        }
        if let Some(metadata) = &self.metadata {
            writer.write(metadata.as_bytes())?;
        }
        for hash in &self.hash_table {
            writer.write_all(hash.as_bytes())?;
        }
        writer.write_all(&self.qti_signature)?;
        writer.write_all(&self.qti_certificate_chain)?;
        writer.write_all(&self.signature)?;
        writer.write_all(&self.certificate_chain)?;
        if padding {
            let padding = vec![self.padding.content; self.padding.len];
            writer.write(&padding)?;
        }

        Ok(())
    }

    /// Get the length of the segment in bytes.
    pub fn len(&self) -> usize {
        let mut len = match self.mbn_header {
            MbnHeader::V3Len40(_) | MbnHeader::V5(_) => 40,
            MbnHeader::V3Len80(_) => 80,
            MbnHeader::V6(_) => 48,
        };

        if self.qti_metadata.is_some() {
            len += 120;
        }
        if self.metadata.is_some() {
            len += 120;
        }
        len += self.hash_table.len() * 48;
        len += self.qti_signature.len();
        len += self.qti_certificate_chain.len();
        len += self.signature.len();
        len += self.certificate_chain.len();
        len += self.padding.len;
        len
    }

    /// Adjust field values of the MBN header to suitable values and the length of padding bytes.
    ///
    /// * `Padding_to`: pad the segment to a specified size.
    pub fn adjust(&mut self, padding_to: usize) {
        self.mbn_header.adjust_header_version();
        self.mbn_header.adjust_image_src();
        match &mut self.mbn_header {
            MbnHeader::V3Len40(header) => {
                header.code_size = (self.hash_table.len() * 48) as u32;
                header.signature_size = self.signature.len() as u32;
                header.cert_chain_size = self.certificate_chain.len() as u32;
            }
            MbnHeader::V3Len80(header) => {
                header.code_size = (self.hash_table.len() * 48) as u32;
                header.signature_size = self.signature.len() as u32;
                header.cert_chain_size = self.certificate_chain.len() as u32;
            }
            MbnHeader::V5(header) => {
                header.code_size = (self.hash_table.len() * 48) as u32;
                header.qti_signature_size = self.qti_signature.len() as u32;
                header.qti_cert_chain_size = self.qti_certificate_chain.len() as u32;
                header.signature_size = self.signature.len() as u32;
                header.cert_chain_size = self.certificate_chain.len() as u32;
            }
            MbnHeader::V6(header) => {
                header.qti_metadata_size = if self.qti_metadata.is_some() { 120 } else { 0 };
                header.metadata_size = if self.metadata.is_some() { 120 } else { 0 };
                header.code_size = (self.hash_table.len() * 48) as u32;
                header.qti_signature_size = self.qti_signature.len() as u32;
                header.qti_cert_chain_size = self.qti_certificate_chain.len() as u32;
                header.signature_size = self.signature.len() as u32;
                header.cert_chain_size = self.certificate_chain.len() as u32;
            }
        }
        self.mbn_header.adjust_image_size();

        let len_no_padding = self.len() - self.padding.len;
        if len_no_padding >= padding_to {
            self.padding.len = 0;
        } else {
            self.padding.len = padding_to - len_no_padding;
        }
    }
}
