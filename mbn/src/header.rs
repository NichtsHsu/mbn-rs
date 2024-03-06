use crate::{
    byte_read::{ByteRead, ByteReader},
    error::ParseError,
};

/// Magic number of [`MbnHeaderV3Len80`].
pub const HEADER_V3_MAGIC: u32 = 0x73D71034;

/// MBN image IDs.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MbnImageId {
    #[default]
    None = 0x00,
    OemSbl = 0x01,
    Amss = 0x02,
    Ocbl = 0x03,
    Hash = 0x04,
    Appbl = 0x05,
    Apps = 0x06,
    HostDl = 0x07,
    Dsp1 = 0x08,
    Fsbl = 0x09,
    Dbl = 0x0A,
    Osbl = 0x0B,
    Dsp2 = 0x0C,
    Ehostdl = 0x0D,
    Nandprg = 0x0E,
    Norprg = 0x0F,
    Ramfs1 = 0x10,
    Ramfs2 = 0x11,
    AdspQ5 = 0x12,
    AppsKernel = 0x13,
    BackupRamfs = 0x14,
    Sbl1 = 0x15,
    Sbl2 = 0x16,
    Rpm = 0x17,
    Sbl3 = 0x18,
    Tz = 0x19,
    SsdKeys = 0x1A,
    Gen = 0x1B,
    Dsp3 = 0x1C,
    Acdb = 0x1D,
    Wdt = 0x1E,
    Mba = 0x1F,
}

/// MBN header version 3 (40 bytes) representation.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbnHeaderV3Len40 {
    /// Identifies the type of image this header represents. In the hash table segment, usually be [`MbnImageId::None`].
    pub image_id: MbnImageId,
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
    /// Identifies the type of image this header represents. In the hash table segment, usually be [`MbnImageId::None`].
    pub image_id: MbnImageId,
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
    /// Identifies the type of image this header represents. In the hash table segment, usually be [`MbnImageId::None`].
    pub image_id: MbnImageId,
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
    /// Identifies the type of image this header represents. In the hash table segment, usually be [`MbnImageId::None`].
    pub image_id: MbnImageId,
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

/// MBN header representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MbnHeader {
    V3Len40(MbnHeaderV3Len40),
    V3Len80(MbnHeaderV3Len80),
    V5(MbnHeaderV5),
    V6(MbnHeaderV6),
}

impl MbnHeaderV3Len40 {
    /// Convert itself to a 40 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; 40] {
        unsafe { &*(self as *const _ as *const [u8; 40]) }
    }

    /// Set [`header_version`](MbnHeaderV3Len40::header_version) to 3.
    pub fn adjust_header_version(&mut self) {
        self.header_version = 3;
    }

    /// Set [`image_src`](MbnHeaderV3Len40::image_src) to 40.
    pub fn adjust_image_src(&mut self) {
        self.image_src = 40;
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
    pub fn as_bytes(&self) -> &[u8; 80] {
        unsafe { &*(self as *const _ as *const [u8; 80]) }
    }

    /// Set [`image_src`](MbnHeaderV3Len80::image_src) to 80.
    pub fn adjust_image_src(&mut self) {
        self.image_src = 80;
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
    pub fn as_bytes(&self) -> &[u8; 40] {
        unsafe { &*(self as *const _ as *const [u8; 40]) }
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
    pub fn as_bytes(&self) -> &[u8; 48] {
        unsafe { &*(self as *const _ as *const [u8; 48]) }
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

impl MbnHeader {
    /// Set `header_version` to a suitable value if the header has this field.
    pub fn adjust_header_version(&mut self) {
        match self {
            Self::V3Len40(header) => header.adjust_header_version(),
            Self::V3Len80(_) => (),
            Self::V5(header) => header.adjust_header_version(),
            Self::V6(header) => header.adjust_header_version(),
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
        }
    }

    /// Convert header to byte slice without copy.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V3Len40(header) => header.as_bytes(),
            Self::V3Len80(header) => header.as_bytes(),
            Self::V5(header) => header.as_bytes(),
            Self::V6(header) => header.as_bytes(),
        }
    }
}

impl std::fmt::Display for MbnImageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MbnImageId::None => write!(f, "None ({:#x})", *self as u32),
            MbnImageId::OemSbl => write!(f, "OemSbl ({:#x})", *self as u32),
            MbnImageId::Amss => write!(f, "Amss ({:#x})", *self as u32),
            MbnImageId::Ocbl => write!(f, "Ocbl ({:#x})", *self as u32),
            MbnImageId::Hash => write!(f, "Hash ({:#x})", *self as u32),
            MbnImageId::Appbl => write!(f, "Appbl ({:#x})", *self as u32),
            MbnImageId::Apps => write!(f, "Apps ({:#x})", *self as u32),
            MbnImageId::HostDl => write!(f, "HostDl ({:#x})", *self as u32),
            MbnImageId::Dsp1 => write!(f, "Dsp1 ({:#x})", *self as u32),
            MbnImageId::Fsbl => write!(f, "Fsbl ({:#x})", *self as u32),
            MbnImageId::Dbl => write!(f, "Dbl ({:#x})", *self as u32),
            MbnImageId::Osbl => write!(f, "Osbl ({:#x})", *self as u32),
            MbnImageId::Dsp2 => write!(f, "Dsp2 ({:#x})", *self as u32),
            MbnImageId::Ehostdl => write!(f, "Ehostdl ({:#x})", *self as u32),
            MbnImageId::Nandprg => write!(f, "Nandprg ({:#x})", *self as u32),
            MbnImageId::Norprg => write!(f, "Norprg ({:#x})", *self as u32),
            MbnImageId::Ramfs1 => write!(f, "Ramfs1 ({:#x})", *self as u32),
            MbnImageId::Ramfs2 => write!(f, "Ramfs2 ({:#x})", *self as u32),
            MbnImageId::AdspQ5 => write!(f, "AdspQ5 ({:#x})", *self as u32),
            MbnImageId::AppsKernel => write!(f, "AppsKernel ({:#x})", *self as u32),
            MbnImageId::BackupRamfs => write!(f, "BackupRamfs ({:#x})", *self as u32),
            MbnImageId::Sbl1 => write!(f, "Sbl1 ({:#x})", *self as u32),
            MbnImageId::Sbl2 => write!(f, "Sbl2 ({:#x})", *self as u32),
            MbnImageId::Rpm => write!(f, "Rpm ({:#x})", *self as u32),
            MbnImageId::Sbl3 => write!(f, "Sbl3 ({:#x})", *self as u32),
            MbnImageId::Tz => write!(f, "Tz ({:#x})", *self as u32),
            MbnImageId::SsdKeys => write!(f, "SsdKeys ({:#x})", *self as u32),
            MbnImageId::Gen => write!(f, "Gen ({:#x})", *self as u32),
            MbnImageId::Dsp3 => write!(f, "Dsp3 ({:#x})", *self as u32),
            MbnImageId::Acdb => write!(f, "Acdb ({:#x})", *self as u32),
            MbnImageId::Wdt => write!(f, "Wdt ({:#x})", *self as u32),
            MbnImageId::Mba => write!(f, "Mba ({:#x})", *self as u32),
        }
    }
}

impl std::fmt::Display for MbnHeaderV3Len40 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Image ID: {}", self.image_id as MbnImageId)?;
        writeln!(f, "Header Version: {}", self.header_version as u32)?;
        writeln!(f, "Image Source: {:#010x}", self.image_src as u32)?;
        writeln!(f, "Image Destination: {:#010x}", self.image_dest_ptr as u32)?;
        writeln!(f, "Image Size: {} bytes", self.image_size as u32)?;
        writeln!(f, "Code Size: {} bytes", self.code_size as u32)?;
        writeln!(
            f,
            "OEM Signature Pointer: {:#010x}",
            self.signature_ptr as u32
        )?;
        writeln!(
            f,
            "OEM Signature Size: {} bytes",
            self.signature_size as u32
        )?;
        writeln!(
            f,
            "OEM Certificate Chain Pointer: {:#010x}",
            self.cert_chain_ptr as u32
        )?;
        write!(
            f,
            "OEM Certificate Chain Size: {} bytes",
            self.cert_chain_size as u32
        )
    }
}

impl std::fmt::Display for MbnHeaderV3Len80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Flash Type Codeword: {:#010x}", self.codeword as u32)?;
        writeln!(f, "Magic: {:#010x}", self.magic as u32)?;
        writeln!(f, "Image ID: {}", self.image_id as MbnImageId)?;
        writeln!(f, "Image Source: {:#010x}", self.image_src as u32)?;
        writeln!(f, "Image Destination: {:#010x}", self.image_dest_ptr as u32)?;
        writeln!(f, "Image Size: {} bytes", self.image_size as u32)?;
        writeln!(f, "Code Size: {} bytes", self.code_size as u32)?;
        writeln!(
            f,
            "OEM Signature Pointer: {:#010x}",
            self.signature_ptr as u32
        )?;
        writeln!(
            f,
            "OEM Signature Size: {} bytes",
            self.signature_size as u32
        )?;
        writeln!(
            f,
            "OEM Certificate Chain Pointer: {:#010x}",
            self.cert_chain_ptr as u32
        )?;
        write!(
            f,
            "OEM Certificate Chain Size: {} bytes",
            self.cert_chain_size as u32
        )
    }
}

impl std::fmt::Display for MbnHeaderV5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Image ID: {}", self.image_id as MbnImageId)?;
        writeln!(f, "Header Version: {}", self.header_version as u32)?;
        writeln!(
            f,
            "QTI Signature Size: {} bytes",
            self.qti_signature_size as u32
        )?;
        writeln!(
            f,
            "QTI certificate chain size: {} bytes",
            self.qti_cert_chain_size as u32
        )?;
        writeln!(f, "Image Size: {} bytes", self.image_size as u32)?;
        writeln!(f, "Code Size: {} bytes", self.code_size as u32)?;
        writeln!(
            f,
            "OEM Signature Pointer: {:#010x}",
            self.signature_ptr as u32
        )?;
        writeln!(
            f,
            "OEM Signature Size: {} bytes",
            self.signature_size as u32
        )?;
        writeln!(
            f,
            "OEM Certificate Chain Pointer: {:#010x}",
            self.cert_chain_ptr as u32
        )?;
        write!(
            f,
            "OEM Certificate Chain Size: {} bytes",
            self.cert_chain_size as u32
        )
    }
}

impl std::fmt::Display for MbnHeaderV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Image ID: {}", self.image_id as MbnImageId)?;
        writeln!(f, "Header Version: {}", self.header_version as u32)?;
        writeln!(
            f,
            "QTI Signature Size: {} bytes",
            self.qti_signature_size as u32
        )?;
        writeln!(
            f,
            "QTI certificate chain size: {} bytes",
            self.qti_cert_chain_size as u32
        )?;
        writeln!(f, "Image Size: {} bytes", self.image_size as u32)?;
        writeln!(f, "Code Size: {} bytes", self.code_size as u32)?;
        writeln!(
            f,
            "OEM Signature Pointer: {:#010x}",
            self.signature_ptr as u32
        )?;
        writeln!(
            f,
            "OEM Signature Size: {} bytes",
            self.signature_size as u32
        )?;
        writeln!(
            f,
            "OEM Certificate Chain Pointer: {:#010x}",
            self.cert_chain_ptr as u32
        )?;
        writeln!(
            f,
            "OEM certificate Chain Size: {} bytes",
            self.cert_chain_size as u32
        )?;
        writeln!(
            f,
            "QTI Metadata Size: {} bytes",
            self.qti_metadata_size as u32
        )?;
        write!(f, "OEM Metadata Size: {} bytes", self.metadata_size as u32)
    }
}

impl std::fmt::Display for MbnHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MbnHeader::V3Len40(header) => header.fmt(f),
            MbnHeader::V3Len80(header) => header.fmt(f),
            MbnHeader::V5(header) => header.fmt(f),
            MbnHeader::V6(header) => header.fmt(f),
        }
    }
}

impl TryFrom<[u8; 40]> for MbnHeaderV3Len40 {
    type Error = ParseError;

    fn try_from(value: [u8; 40]) -> Result<Self, Self::Error> {
        let image_id = u32::from_le_bytes(value[0..4].try_into().unwrap());
        if image_id > MbnImageId::Mba as u32 {
            return Err(ParseError::UnsupportedImageId(image_id));
        }
        Ok(unsafe { std::mem::transmute(value) })
    }
}

impl From<MbnHeaderV3Len40> for [u8; 40] {
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
            TryFrom::<[u8; std::mem::size_of::<Self>()]>::try_from(
                buffer
                    .current()
                    .get(0..std::mem::size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            )?,
            std::mem::size_of::<Self>(),
        ))
    }
}

impl TryFrom<[u8; 80]> for MbnHeaderV3Len80 {
    type Error = ParseError;

    fn try_from(value: [u8; 80]) -> Result<Self, Self::Error> {
        let image_id = u32::from_le_bytes(value[0..4].try_into().unwrap());
        if image_id > MbnImageId::Mba as u32 {
            return Err(ParseError::UnsupportedImageId(image_id));
        }
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV3Len80> for [u8; 80] {
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
            TryFrom::<[u8; std::mem::size_of::<Self>()]>::try_from(
                buffer
                    .current()
                    .get(0..std::mem::size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            )?,
            std::mem::size_of::<Self>(),
        ))
    }
}

impl TryFrom<[u8; 40]> for MbnHeaderV5 {
    type Error = ParseError;

    fn try_from(value: [u8; 40]) -> Result<Self, Self::Error> {
        let image_id = u32::from_le_bytes(value[0..4].try_into().unwrap());
        if image_id > MbnImageId::Mba as u32 {
            return Err(ParseError::UnsupportedImageId(image_id));
        }
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV5> for [u8; 40] {
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
            TryFrom::<[u8; std::mem::size_of::<Self>()]>::try_from(
                buffer
                    .current()
                    .get(0..std::mem::size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            )?,
            std::mem::size_of::<Self>(),
        ))
    }
}

impl TryFrom<[u8; 48]> for MbnHeaderV6 {
    type Error = ParseError;

    fn try_from(value: [u8; 48]) -> Result<Self, Self::Error> {
        let image_id = u32::from_le_bytes(value[0..4].try_into().unwrap());
        if image_id > MbnImageId::Mba as u32 {
            return Err(ParseError::UnsupportedImageId(image_id));
        }
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MbnHeaderV6> for [u8; 48] {
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
            TryFrom::<[u8; std::mem::size_of::<Self>()]>::try_from(
                buffer
                    .current()
                    .get(0..std::mem::size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            )?,
            std::mem::size_of::<Self>(),
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
            HEADER_V3_MAGIC => {
                let (header, count) = MbnHeaderV3Len80::read(buffer)?;
                (MbnHeader::V3Len80(header), count)
            }
            _ => return Err(ParseError::UnsupportedHeaderVersion(header_version)),
        })
    }
}
