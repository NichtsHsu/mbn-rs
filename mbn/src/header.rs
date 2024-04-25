use std::mem::size_of;

use crate::{
    byte_read::{ByteRead, ByteReader},
    error::ParseError,
};

/// Image ID representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ImageId(pub u32);

/// Magic number of [`MbnHeaderV3Len80`].
pub const HEADER_V3_MAGIC: u32 = 0x73D71034;

/// MBN header version 3 (40 bytes) representation.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbnHeaderV3Len40 {
    /// Identifies the type of image this header represents. In the hash table segment, usually be 0.
    pub image_id: ImageId,
    /// Header version number.
    pub header_version: u32,
    /// Location of image in flash or e-hostdl in RAM. This is given in byte offset from beginning of flash/RAM.
    pub image_src: u32,
    /// Pointer to location to store RPM_SBL/e-hostdl in RAM. Also, entry point at which execution begins.
    pub image_dest_ptr: u32,
    /// Size of complete image in bytes.
    pub image_size: u32,
    /// Size of code region of image in bytes.
    pub code_size: u32,
    /// Pointer to images OEM signature.
    pub signature_ptr: u32,
    /// Size of the OEM signature in bytes.
    pub signature_size: u32,
    /// Pointer to the chain of OEM certificate associated with the image.
    pub cert_chain_ptr: u32,
    /// Size of the OEM certificate chain in bytes.
    pub cert_chain_size: u32,
}

/// MBN header version 3 (80 bytes) representation.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbnHeaderV3Len80 {
    /// Codeword defining flash type information (usually `0x844BDCD1`).
    pub codeword: u32,
    /// Magic number, see [`HEADER_V3_MAGIC`].
    pub magic: u32,
    /// Identifies the type of image this header represents. In the hash table segment, usually be 0.
    pub image_id: ImageId,
    _reserved1: u32,
    _reserved2: u32,
    /// Location of image in flash or e-hostdl in RAM. This is given in byte offset from beginning of flash/RAM.
    pub image_src: u32,
    /// Pointer to location to store RPM_SBL/e-hostdl in RAM. Also, entry point at which execution begins.
    pub image_dest_ptr: u32,
    /// Size of complete image in bytes.
    pub image_size: u32,
    /// Size of code region of image in bytes.
    pub code_size: u32,
    /// Pointer to images OEM signature.
    pub signature_ptr: u32,
    /// Size of the OEM signature in bytes.
    pub signature_size: u32,
    /// Pointer to the chain of OEM certificates associated with the image.
    pub cert_chain_ptr: u32,
    /// Size of the OEM certificate chain in bytes.
    pub cert_chain_size: u32,
    _reserved3: u32,
    _reserved4: u32,
    _reserved5: u32,
    _reserved6: u32,
    _reserved7: u32,
    _reserved8: u32,
    _reserved9: u32,
}

/// MBN header version 5 representation.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbnHeaderV5 {
    /// Identifies the type of image this header represents. In the hash table segment, usually be 0.
    pub image_id: ImageId,
    /// Header version number.
    pub header_version: u32,
    /// Size of the QTI signature in bytes.
    pub qti_signature_size: u32,
    /// Size of the QTI certificate chain in bytes.
    pub qti_cert_chain_size: u32,
    /// Size of complete image in bytes.
    pub image_size: u32,
    /// Size of code region of image in bytes.
    pub code_size: u32,
    /// Pointer to images OEM signature.
    pub signature_ptr: u32,
    /// Size of the OEM signature in bytes.
    pub signature_size: u32,
    /// Pointer to the chain of OEM certificates associated with the image.
    pub cert_chain_ptr: u32,
    /// Size of the OEM certificate chain in bytes.
    pub cert_chain_size: u32,
}

/// MBN header version 6 representation.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbnHeaderV6 {
    /// Identifies the type of image this header represents. In the hash table segment, usually be 0.
    pub image_id: ImageId,
    /// Header version number.
    pub header_version: u32,
    /// Size of the QTI signature in bytes.
    pub qti_signature_size: u32,
    /// Size of the QTI certificate chain in bytes.
    pub qti_cert_chain_size: u32,
    /// Size of complete image in bytes.
    pub image_size: u32,
    /// Size of code region of image in bytes.
    pub code_size: u32,
    /// Pointer to images OEM signature.
    pub signature_ptr: u32,
    /// Size of the OEM signature in bytes.
    pub signature_size: u32,
    /// Pointer to the chain of OEM certificates associated with the image.
    pub cert_chain_ptr: u32,
    /// Size of the OEM certificate chain in bytes.
    pub cert_chain_size: u32,
    /// Size of the QTI metadata in bytes.
    pub qti_metadata_size: u32,
    /// Size of the OEM metadata in bytes.
    pub metadata_size: u32,
}

/// MBN header version 7 representation.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbnHeaderV7 {
    /// Identifies the type of image this header represents. In the hash table segment, usually be 0.
    pub image_id: ImageId,
    /// Header version number.
    pub header_version: u32,
    /// Size of the common metadata in bytes.
    pub common_meta_size: u32,
    /// Size of the QTI metadata in bytes.
    pub qti_metadata_size: u32,
    /// Size of the OEM metadata in bytes.
    pub metadata_size: u32,
    /// Size of code region of image in bytes.
    pub code_size: u32,
    /// Size of the QTI signature in bytes.
    pub qti_signature_size: u32,
    /// Size of the QTI certificate chain in bytes.
    pub qti_cert_chain_size: u32,
    /// Size of the OEM signature in bytes.
    pub signature_size: u32,
    /// Size of the OEM certificate chain in bytes.
    pub cert_chain_size: u32,
}

/// MBN header representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MbnHeader {
    V3Len40(MbnHeaderV3Len40),
    V3Len80(MbnHeaderV3Len80),
    V5(MbnHeaderV5),
    V6(MbnHeaderV6),
    V7(MbnHeaderV7),
}

impl ImageId {
    pub const NONE: ImageId = ImageId(0x00);
    pub const OEMSBL: ImageId = ImageId(0x01);
    pub const AMSS: ImageId = ImageId(0x02);
    pub const QCSBL: ImageId = ImageId(0x03);
    pub const HASH: ImageId = ImageId(0x04);
    pub const APPSBL: ImageId = ImageId(0x05);
    pub const APPS: ImageId = ImageId(0x06);
    pub const HOSTDL: ImageId = ImageId(0x07);
    pub const DSP1: ImageId = ImageId(0x08);
    pub const FSBL: ImageId = ImageId(0x09);
    pub const DBL: ImageId = ImageId(0x0a);
    pub const OSBL: ImageId = ImageId(0x0b);
    pub const DSP2: ImageId = ImageId(0x0c);
    pub const EHOSTDL: ImageId = ImageId(0x0d);
    pub const NANDPRG: ImageId = ImageId(0x0e);
    pub const NORPRG: ImageId = ImageId(0x0f);
    pub const RAMFS1: ImageId = ImageId(0x10);
    pub const RAMFS2: ImageId = ImageId(0x11);
    pub const ADSP_Q5: ImageId = ImageId(0x12);
    pub const APPS_KERNEL: ImageId = ImageId(0x13);
    pub const BACKUP_RAMFS: ImageId = ImageId(0x14);
    pub const SBL1: ImageId = ImageId(0x15);
    pub const SBL2: ImageId = ImageId(0x16);
    pub const RPM: ImageId = ImageId(0x17);
    pub const SBL3: ImageId = ImageId(0x18);
    pub const TZ: ImageId = ImageId(0x19);
    /* 0x1a-0x1f deprecated. */
    pub const PSI: ImageId = ImageId(0x20);
}

impl MbnHeaderV3Len40 {
    /// Convert itself to a 40 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<MbnHeaderV3Len40>()] {
        unsafe { &*(self as *const _ as *const _) }
    }

    /// Set [`header_version`](MbnHeaderV3Len40::header_version) to 3.
    pub fn adjust_header_version(&mut self) {
        self.header_version = 3;
    }

    /// Set [`image_src`](MbnHeaderV3Len40::image_src) to 40.
    pub fn adjust_image_src(&mut self) {
        self.image_src = size_of::<Self>() as u32;
    }

    /// Set [`image_size`](MbnHeaderV3Len40::image_size) to the sum of
    /// [`code_size`](MbnHeaderV3Len40::code_size),
    /// [`signature_size`](MbnHeaderV3Len40::signature_size) and
    /// [`cert_chain_size`](MbnHeaderV3Len40::cert_chain_size).
    pub fn adjust_image_size(&mut self) {
        self.image_size = self.code_size + self.signature_size + self.cert_chain_size;
    }
}

impl MbnHeaderV3Len80 {
    /// Convert itself to a 80 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<MbnHeaderV3Len80>()] {
        unsafe { &*(self as *const _ as *const _) }
    }

    /// Set [`image_src`](MbnHeaderV3Len80::image_src) to 80.
    pub fn adjust_image_src(&mut self) {
        self.image_src = size_of::<Self>() as u32;
    }

    /// Set [`image_size`](MbnHeaderV3Len80::image_size) to the sum of
    /// [`code_size`](MbnHeaderV3Len80::code_size),
    /// [`signature_size`](MbnHeaderV3Len80::signature_size) and
    /// [`cert_chain_size`](MbnHeaderV3Len80::cert_chain_size).
    pub fn adjust_image_size(&mut self) {
        self.image_size = self.code_size + self.signature_size + self.cert_chain_size;
    }
}

impl MbnHeaderV5 {
    /// Convert itself to a 40 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<MbnHeaderV5>()] {
        unsafe { &*(self as *const _ as *const _) }
    }

    /// Set [`header_version`](MbnHeaderV5::header_version) to 5.
    pub fn adjust_header_version(&mut self) {
        self.header_version = 5;
    }

    /// Set [`image_size`](MbnHeaderV5::image_size) to the sum of
    /// [`code_size`](MbnHeaderV5::code_size),
    /// [`qti_signature_size`](MbnHeaderV5::qti_signature_size),
    /// [`qti_cert_chain_size`](MbnHeaderV5::qti_cert_chain_size),
    /// [`signature_size`](MbnHeaderV5::signature_size) and
    /// [`cert_chain_size`](MbnHeaderV5::cert_chain_size).
    pub fn adjust_image_size(&mut self) {
        self.image_size = self.code_size
            + self.qti_signature_size
            + self.qti_cert_chain_size
            + self.signature_size
            + self.cert_chain_size;
    }
}

impl MbnHeaderV6 {
    /// Convert itself to a 48 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<MbnHeaderV6>()] {
        unsafe { &*(self as *const _ as *const _) }
    }

    /// Set [`header_version`](MbnHeaderV6::header_version) to 6.
    pub fn adjust_header_version(&mut self) {
        self.header_version = 6;
    }

    /// Set [`image_size`](MbnHeaderV6::image_size) to the sum of
    /// [`code_size`](MbnHeaderV6::code_size),
    /// [`qti_signature_size`](MbnHeaderV6::qti_signature_size),
    /// [`qti_cert_chain_size`](MbnHeaderV6::qti_cert_chain_size),
    /// [`signature_size`](MbnHeaderV6::signature_size) and
    /// [`cert_chain_size`](MbnHeaderV6::cert_chain_size).
    pub fn adjust_image_size(&mut self) {
        self.image_size = self.code_size
            + self.qti_signature_size
            + self.qti_cert_chain_size
            + self.signature_size
            + self.cert_chain_size;
    }
}

impl MbnHeaderV7 {
    /// Convert itself to a 48 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<MbnHeaderV7>()] {
        unsafe { &*(self as *const _ as *const _) }
    }

    /// Set [`header_version`](MbnHeaderV7::header_version) to 7.
    pub fn adjust_header_version(&mut self) {
        self.header_version = 7;
    }
}

impl MbnHeader {
    /// Set `header_version` to a suitable value if the header has this field.
    pub fn adjust_header_version(&mut self) {
        match self {
            Self::V3Len40(header) => header.adjust_header_version(),
            Self::V3Len80(_) => (),
            Self::V5(header) => header.adjust_header_version(),
            Self::V6(header) => header.adjust_header_version(),
            Self::V7(header) => header.adjust_header_version(),
        }
    }

    /// Set `image_src` to a suitable value if the header has this field.
    pub fn adjust_image_src(&mut self) {
        match self {
            Self::V3Len40(header) => header.adjust_image_src(),
            Self::V3Len80(header) => header.adjust_image_src(),
            _ => (),
        }
    }

    /// Set `image_size` to a suitable value.
    pub fn adjust_image_size(&mut self) {
        match self {
            Self::V3Len40(header) => header.adjust_image_size(),
            Self::V3Len80(header) => header.adjust_image_size(),
            Self::V5(header) => header.adjust_image_size(),
            Self::V6(header) => header.adjust_image_size(),
            _ => (),
        }
    }

    /// Convert header to byte slice without copy.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V3Len40(header) => header.as_bytes(),
            Self::V3Len80(header) => header.as_bytes(),
            Self::V5(header) => header.as_bytes(),
            Self::V6(header) => header.as_bytes(),
            Self::V7(header) => header.as_bytes(),
        }
    }
}

impl std::fmt::Display for ImageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::NONE => write!(f, "NONE ({:#x})", self.0),
            &Self::OEMSBL => write!(
                f,
                "OEM-SBL ({:#x}) - OEM Secondary Boot Loader Image",
                self.0
            ),
            &Self::AMSS => write!(
                f,
                "AMSS ({:#x}) - Advanced Mobile Subscriber Software Image",
                self.0
            ),
            &Self::QCSBL => write!(
                f,
                "QCSBL ({:#x}) - Qualcomm Secondary Boot Loader Image",
                self.0
            ),
            &Self::HASH => write!(f, "HASH ({:#x}) - Hash Image", self.0),
            &Self::APPSBL => write!(f, "APPSBL ({:#x}) - Applications Boot Loader Image", self.0),
            &Self::APPS => write!(f, "APPS ({:#x}) - Applications Image", self.0),
            &Self::HOSTDL => write!(f, "HOSTDL ({:#x}) - Host Download Image", self.0),
            &Self::DSP1 => write!(f, "DSP1 ({:#x}) - Digital Signal Processor 1 Image", self.0),
            &Self::FSBL => write!(f, "FSBL ({:#x}) - Fail Safe Boot Loader Image", self.0),
            &Self::DBL => write!(f, "DBL ({:#x}) - Device Boot Loader Image", self.0),
            &Self::OSBL => write!(
                f,
                "OSBL ({:#x}) - Operating System Boot Loader Image",
                self.0
            ),
            &Self::DSP2 => write!(f, "DSP2 ({:#x}) - Digital Signal Processor 2 Image", self.0),
            &Self::EHOSTDL => write!(f, "EHOSTDL ({:#x}) - Emergency Host Download Image", self.0),
            &Self::NANDPRG => {
                write!(f, "NANDPRG ({:#x}) - NAND Programmer IMage", self.0)
            }
            &Self::NORPRG => write!(f, "NORPRG ({:#x}) - NOR Programmer Image", self.0),
            &Self::RAMFS1 => {
                write!(f, "RAMFS1 ({:#x}) - RAM File System 1 Image", self.0)
            }
            &Self::RAMFS2 => {
                write!(f, "RAMFS2 ({:#x}) - RAM File System 2 Image", self.0)
            }
            &Self::ADSP_Q5 => write!(
                f,
                "ADSP-Q5 ({:#x} - Application Digital Signal Processor Q5 Image)",
                self.0
            ),
            &Self::APPS_KERNEL => {
                write!(f, "APPS-KERNEL ({:#x}) - Applications Kernel Image", self.0)
            }
            &Self::BACKUP_RAMFS => write!(
                f,
                "BACKUP-RAMFS ({:#x}) - Backup RAM File System Image",
                self.0
            ),
            &Self::SBL1 => write!(f, "SBL1 ({:#x}) - Secondary Boot Loader 1 Image", self.0),
            &Self::SBL2 => write!(f, "SBL2 ({:#x}) - Secondary Boot Loader 2 Image", self.0),
            &Self::RPM => write!(f, "RPM ({:#x}) - Resource Power Manager Image", self.0),
            &Self::SBL3 => write!(f, "SBL3 ({:#x}) - Secondary Boot Loader 3 Image", self.0),
            &Self::TZ => write!(f, "TZ ({:#x}) - Trust Zone Image", self.0),
            &Self::PSI => write!(f, "PSI ({:#x}) - PMIC Software Image", self.0),
            _ => write!(f, "/* Unknown */ ({:#x})", self.0),
        }
    }
}

impl std::fmt::Display for MbnHeaderV3Len40 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Image ID: {}", { self.image_id })?;
        writeln!(f, "Header Version: {}", { self.header_version })?;
        writeln!(f, "Image Source: {:#010x}", { self.image_src })?;
        writeln!(f, "Image Destination: {:#010x}", { self.image_dest_ptr })?;
        writeln!(f, "Image Size: {} bytes", { self.image_size })?;
        writeln!(f, "Code Size: {} bytes", { self.code_size })?;
        writeln!(f, "OEM Signature Pointer: {:#010x}", { self.signature_ptr })?;
        writeln!(f, "OEM Signature Size: {} bytes", { self.signature_size })?;
        writeln!(f, "OEM Certificate Chain Pointer: {:#010x}", {
            self.cert_chain_ptr
        })?;
        write!(f, "OEM Certificate Chain Size: {} bytes", {
            self.cert_chain_size
        })
    }
}

impl std::fmt::Display for MbnHeaderV3Len80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Flash Type Codeword: {:#010x}", { self.codeword })?;
        writeln!(f, "Magic: {:#010x}", { self.magic })?;
        writeln!(f, "Image ID: {}", { self.image_id })?;
        writeln!(f, "Image Source: {:#010x}", { self.image_src })?;
        writeln!(f, "Image Destination: {:#010x}", { self.image_dest_ptr })?;
        writeln!(f, "Image Size: {} bytes", { self.image_size })?;
        writeln!(f, "Code Size: {} bytes", { self.code_size })?;
        writeln!(f, "OEM Signature Pointer: {:#010x}", { self.signature_ptr })?;
        writeln!(f, "OEM Signature Size: {} bytes", { self.signature_size })?;
        writeln!(f, "OEM Certificate Chain Pointer: {:#010x}", {
            self.cert_chain_ptr
        })?;
        write!(f, "OEM Certificate Chain Size: {} bytes", {
            self.cert_chain_size
        })
    }
}

impl std::fmt::Display for MbnHeaderV5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Image ID: {}", { self.image_id })?;
        writeln!(f, "Header Version: {}", { self.header_version })?;
        writeln!(f, "QTI Signature Size: {} bytes", {
            self.qti_signature_size
        })?;
        writeln!(f, "QTI certificate chain size: {} bytes", {
            self.qti_cert_chain_size
        })?;
        writeln!(f, "Image Size: {} bytes", { self.image_size })?;
        writeln!(f, "Code Size: {} bytes", { self.code_size })?;
        writeln!(f, "OEM Signature Pointer: {:#010x}", { self.signature_ptr })?;
        writeln!(f, "OEM Signature Size: {} bytes", { self.signature_size })?;
        writeln!(f, "OEM Certificate Chain Pointer: {:#010x}", {
            self.cert_chain_ptr
        })?;
        write!(f, "OEM Certificate Chain Size: {} bytes", {
            self.cert_chain_size
        })
    }
}

impl std::fmt::Display for MbnHeaderV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Image ID: {}", { self.image_id })?;
        writeln!(f, "Header Version: {}", { self.header_version })?;
        writeln!(f, "QTI Signature Size: {} bytes", {
            self.qti_signature_size
        })?;
        writeln!(f, "QTI certificate chain size: {} bytes", {
            self.qti_cert_chain_size
        })?;
        writeln!(f, "Image Size: {} bytes", { self.image_size })?;
        writeln!(f, "Code Size: {} bytes", { self.code_size })?;
        writeln!(f, "OEM Signature Pointer: {:#010x}", { self.signature_ptr })?;
        writeln!(f, "OEM Signature Size: {} bytes", { self.signature_size })?;
        writeln!(f, "OEM Certificate Chain Pointer: {:#010x}", {
            self.cert_chain_ptr
        })?;
        writeln!(f, "OEM certificate Chain Size: {} bytes", {
            self.cert_chain_size
        })?;
        writeln!(f, "QTI Metadata Size: {} bytes", { self.qti_metadata_size })?;
        write!(f, "OEM Metadata Size: {} bytes", { self.metadata_size })
    }
}

impl std::fmt::Display for MbnHeaderV7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Image ID: {}", { self.image_id })?;
        writeln!(f, "Header Version: {}", { self.header_version })?;
        writeln!(f, "Common Metadata Size: {} bytes", {
            self.common_meta_size
        })?;
        writeln!(f, "QTI Metadata Size: {} bytes", { self.qti_metadata_size })?;
        writeln!(f, "OEM Metadata Size: {} bytes", { self.metadata_size })?;
        writeln!(f, "Code Size: {} bytes", { self.code_size })?;
        writeln!(f, "QTI Signature Size: {} bytes", {
            self.qti_signature_size
        })?;
        writeln!(f, "QTI certificate chain size: {} bytes", {
            self.qti_cert_chain_size
        })?;
        writeln!(f, "OEM Signature Size: {} bytes", { self.signature_size })?;
        write!(f, "OEM certificate Chain Size: {} bytes", {
            self.cert_chain_size
        })
    }
}

impl std::fmt::Display for MbnHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MbnHeader::V3Len40(header) => header.fmt(f),
            MbnHeader::V3Len80(header) => header.fmt(f),
            MbnHeader::V5(header) => header.fmt(f),
            MbnHeader::V6(header) => header.fmt(f),
            MbnHeader::V7(header) => header.fmt(f),
        }
    }
}

impl From<u32> for ImageId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ImageId> for u32 {
    fn from(value: ImageId) -> Self {
        value.0
    }
}

impl From<[u8; size_of::<Self>()]> for MbnHeaderV3Len40 {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV3Len40> for [u8; size_of::<MbnHeaderV3Len40>()] {
    fn from(value: MbnHeaderV3Len40) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl Default for MbnHeaderV3Len40 {
    fn default() -> Self {
        let mut header: MbnHeaderV3Len40 = unsafe { std::mem::zeroed() };
        header.header_version = 3;
        header.image_src = 40;
        header
    }
}

impl ByteRead for MbnHeaderV3Len40 {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            From::<[u8; size_of::<Self>()]>::from(
                buffer
                    .current()
                    .get(0..size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            ),
            size_of::<Self>(),
        ))
    }
}

impl From<[u8; size_of::<Self>()]> for MbnHeaderV3Len80 {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV3Len80> for [u8; size_of::<MbnHeaderV3Len80>()] {
    fn from(value: MbnHeaderV3Len80) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl Default for MbnHeaderV3Len80 {
    fn default() -> Self {
        let mut header: MbnHeaderV3Len80 = unsafe { std::mem::zeroed() };
        header.codeword = 0x844BDCD1;
        header.magic = 0x73D71034;
        header.image_src = 80;
        header
    }
}

impl ByteRead for MbnHeaderV3Len80 {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            From::<[u8; size_of::<Self>()]>::from(
                buffer
                    .current()
                    .get(0..size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            ),
            size_of::<Self>(),
        ))
    }
}

impl From<[u8; size_of::<Self>()]> for MbnHeaderV5 {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV5> for [u8; size_of::<MbnHeaderV5>()] {
    fn from(value: MbnHeaderV5) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl Default for MbnHeaderV5 {
    fn default() -> Self {
        let mut header: MbnHeaderV5 = unsafe { std::mem::zeroed() };
        header.header_version = 5;
        header
    }
}

impl ByteRead for MbnHeaderV5 {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            From::<[u8; size_of::<Self>()]>::from(
                buffer
                    .current()
                    .get(0..size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            ),
            size_of::<Self>(),
        ))
    }
}

impl From<[u8; size_of::<Self>()]> for MbnHeaderV6 {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV6> for [u8; size_of::<MbnHeaderV6>()] {
    fn from(value: MbnHeaderV6) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl Default for MbnHeaderV6 {
    fn default() -> Self {
        let mut header: MbnHeaderV6 = unsafe { std::mem::zeroed() };
        header.header_version = 6;
        header
    }
}

impl ByteRead for MbnHeaderV6 {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            From::<[u8; size_of::<Self>()]>::from(
                buffer
                    .current()
                    .get(0..size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            ),
            size_of::<Self>(),
        ))
    }
}

impl From<[u8; size_of::<Self>()]> for MbnHeaderV7 {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV7> for [u8; size_of::<MbnHeaderV7>()] {
    fn from(value: MbnHeaderV7) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl Default for MbnHeaderV7 {
    fn default() -> Self {
        let mut header: MbnHeaderV7 = unsafe { std::mem::zeroed() };
        header.header_version = 7;
        header
    }
}

impl ByteRead for MbnHeaderV7 {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            From::<[u8; size_of::<Self>()]>::from(
                buffer
                    .current()
                    .get(0..size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            ),
            size_of::<Self>(),
        ))
    }
}

impl ByteRead for MbnHeader {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        let header_version: u32 = buffer.peek(4)?;
        Ok(match header_version {
            3 => {
                let (header, count) = MbnHeaderV3Len40::read(buffer)?;
                (MbnHeader::V3Len40(header), count)
            }
            5 => {
                let (header, count) = MbnHeaderV5::read(buffer)?;
                (MbnHeader::V5(header), count)
            }
            6 => {
                let (header, count) = MbnHeaderV6::read(buffer)?;
                (MbnHeader::V6(header), count)
            }
            7 => {
                let (header, count) = MbnHeaderV7::read(buffer)?;
                (MbnHeader::V7(header), count)
            }
            HEADER_V3_MAGIC => {
                let (header, count) = MbnHeaderV3Len80::read(buffer)?;
                (MbnHeader::V3Len80(header), count)
            }
            _ => return Err(ParseError::UnsupportedHeaderVersion(header_version)),
        })
    }
}
