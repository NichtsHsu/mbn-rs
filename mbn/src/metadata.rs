use crate::{
    byte_read::{ByteRead, ByteReader},
    error::ParseError,
};

/// The [`flags`](Metadata::flags) field of [`Metadata`].
///
/// See [`QtiFlagsBuilder`] for build a [`QtiFlags`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QtiFlags(pub u32);

/// Builder for [`QtiFlags`].
#[derive(Clone, Copy, Debug, Default)]
pub struct QtiFlagsBuilder(u32);

/// The QTI metadata and OEM metadata representation.
///
/// Only [`HashTableSegment`](crate::HashTableSegment)
/// with [`MbnHeaderV6`](crate::MbnHeaderV6) has metadata.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// Metadata major version.
    pub major_version: u32,
    /// Metadata minor version.
    pub minor_version: u32,
    /// A 32-bit software type value of the image which specifies the signed image.
    pub software_id: u32,
    /// The hardware ID is composed of JTAG ID.
    pub hardware_id: u32,
    /// A 32-bit value served as CASS account ID for the OEM.
    pub oem_id: u32,
    /// Model ID prevents misuse of images across various models.
    pub model_id: u32,
    /// Required for a TZ application.
    pub app_id: u32,
    /// See [`QtiFlags`].
    pub flags: QtiFlags,
    /// Contains up to 12 unique soc_hw values.
    pub soc_version: [u32; 12],
    /// Contains up to eight serial numbers.
    pub multi_serial_numbers: [u32; 8],
    /// The active root certificate index in MRC (Multiple Root Certificate).
    pub root_cert_index: u32,
    /// Anti-rollback version specifies the minimum supported version.
    pub anti_rollback_version: u32,
}

impl QtiFlags {
    /// RoT (Root of Trust) enablement.
    pub fn rot_en(&self) -> bool {
        self.0 & 1 != 0
    }

    /// Using [`Metadata::soc_version`] in image signing.
    pub fn in_use_soc_hw_version(&self) -> bool {
        self.0 & (1 << 1) != 0
    }

    /// Using serial number in image signing.
    pub fn use_serial_number_in_signing(&self) -> bool {
        self.0 & (1 << 2) != 0
    }

    /// Using [`Metadata::oem_id`] in image signing if **`false`**.
    pub fn oem_id_independent(&self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// Enables revocation and activation in MRC (Multiple Root Certificate).
    ///
    /// * 0: Disable
    /// * 1: Enable
    /// * 2: Enable with serial number binding provided in the [`Metadata::multi_serial_numbers`] field.
    pub fn root_revoke_activate_enable(&self) -> u8 {
        ((self.0 >> 4) & 0b11) as u8
    }

    /// Enables UIE (Unified Image Encryption) key switch.
    ///
    /// * 0: Disable
    /// * 1: Enable
    /// * 2: Enable with serial number binding provided in the [`Metadata::multi_serial_numbers`] field.
    pub fn uie_key_switch_enable(&self) -> u8 {
        ((self.0 >> 6) & 0b11) as u8
    }

    /// Debug field.
    ///
    /// For secure boot v1 and v2:
    ///
    /// * 2: `0` is to be written to the one-time debug override registers
    /// * 3: `1` is to be written to the one-time debug override registers
    ///
    /// For secure boot v3 ([`MbnHeaderV6`](crate::MbnHeaderV6)):
    ///
    /// * 1: `0` is to be written to the one-time debug override registers
    /// * 2: `1` is to be written to the one-time debug override registers
    pub fn debug(&self) -> u8 {
        ((self.0 >> 8) & 0b11) as u8
    }

    /// Using [`Metadata::hardware_id`] in image signing.
    ///
    /// Valid only when [`Metadata::major_version`] is greater than 0.
    pub fn in_use_hw_id(&self) -> bool {
        self.0 & (1 << 10) != 0
    }

    /// Using [`Metadata::app_id`] in image signing if **`false`**.
    ///
    /// Valid only when [`Metadata::major_version`] is greater than 0.
    pub fn model_id_independent(&self) -> bool {
        self.0 & (1 << 11) != 0
    }
}

impl QtiFlagsBuilder {
    fn set_bit(&mut self, bit: u8) {
        self.0 |= 1 << bit;
    }

    fn clear_bit(&mut self, bit: u8) {
        self.0 &= !(1 << bit);
    }

    fn set_value(&mut self, start: u8, end: u8, value: u8) {
        (start..end).for_each(|x| self.clear_bit(x));
        let mask = (1 << end - start) - 1;
        self.0 |= (value as u32 & mask) << start;
    }

    /// Create a new builder.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new builder based on [`QtiFlags`].
    pub fn with(flags: QtiFlags) -> Self {
        Self(flags.0)
    }

    /// Build [`QtiFlags`].
    pub fn build(self) -> QtiFlags {
        QtiFlags(self.0)
    }

    /// Set [`rot_en`](QtiFlags::rot_en()) bit.
    pub fn rot_en(&mut self) {
        self.set_bit(0);
    }

    /// Set [`in_use_soc_hw_version`](QtiFlags::in_use_soc_hw_version()) bit.
    pub fn in_use_soc_hw_version(&mut self) {
        self.set_bit(1);
    }

    /// Set [`use_serial_number_in_signing`](QtiFlags::use_serial_number_in_signing()) bit.
    pub fn use_serial_number_in_signing(&mut self) {
        self.set_bit(2);
    }

    /// Set [`oem_id_independent`](QtiFlags::oem_id_independent()) bit.
    pub fn oem_id_independent(&mut self) {
        self.set_bit(3);
    }

    /// Set [`root_revoke_activate_enable`](QtiFlags::root_revoke_activate_enable()) value.
    pub fn root_revoke_activate_enable(&mut self, value: u8) {
        self.set_value(4, 6, value);
    }

    /// Set [`uie_key_switch_enable`](QtiFlags::uie_key_switch_enable()) value.
    pub fn uie_key_switch_enable(&mut self, value: u8) {
        self.set_value(6, 8, value);
    }

    /// Set [`debug`](QtiFlags::debug()) value.
    pub fn debug(&mut self, value: u8) {
        self.set_value(8, 10, value);
    }

    /// Set [`in_use_hw_id`](QtiFlags::in_use_hw_id()) bit.
    pub fn in_use_hw_id(&mut self) {
        self.set_bit(10);
    }

    /// Set [`model_id_independent`](QtiFlags::model_id_independent()) bit.
    pub fn model_id_independent(&mut self) {
        self.set_bit(11);
    }
}

impl Metadata {
    /// Convert itself to a 120 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; 120] {
        unsafe { &*(self as *const _ as *const [u8; 120]) }
    }

    /// Format [`Metadata`] requires knowing the secure boot version, so
    /// `Display` is not implemented for it.
    pub fn fmt(&self, f: &mut std::fmt::Formatter<'_>, secboot_ver: u32) -> std::fmt::Result {
        writeln!(f, "Major Version: {}", self.major_version as u32)?;
        writeln!(f, "Minor Version: {}", self.minor_version as u32)?;
        writeln!(f, "Software ID: {:#010x}", self.software_id as u32)?;
        writeln!(f, "JTAG ID: {:#010x}", self.hardware_id as u32)?;
        writeln!(f, "OEM ID: {:#010x}", self.oem_id as u32)?;
        writeln!(f, "Model ID: {:#010x}", self.model_id as u32)?;
        writeln!(f, "Application ID: {:#010x}", self.app_id as u32)?;
        writeln!(
            f,
            "RoT (Root of Trust): {}",
            (self.flags as QtiFlags).rot_en()
        )?;
        writeln!(
            f,
            "Use SoC Hardware Versions: {}",
            (self.flags as QtiFlags).in_use_soc_hw_version()
        )?;
        writeln!(
            f,
            "Use Serial Numbers: {}",
            (self.flags as QtiFlags).use_serial_number_in_signing()
        )?;
        writeln!(
            f,
            "Use OEM ID: {}",
            !(self.flags as QtiFlags).oem_id_independent()
        )?;
        writeln!(
            f,
            "Revocation and Activation in MRC (Multiple Root Certificate): {} ({:#x})",
            (self.flags as QtiFlags).root_revoke_activate_enable() > 0,
            (self.flags as QtiFlags).root_revoke_activate_enable()
        )?;
        writeln!(
            f,
            "UIE (Unified Image Encryption) Key Switch: {} ({:#x})",
            (self.flags as QtiFlags).uie_key_switch_enable() > 0,
            (self.flags as QtiFlags).uie_key_switch_enable()
        )?;
        writeln!(
            f,
            "JTAG Debug: {} ({:#x})",
            match secboot_ver {
                1..=2 => ((self.flags as QtiFlags).debug() == 3).to_string(),
                3 => ((self.flags as QtiFlags).debug() == 2).to_string(),
                _ => "/* Unknown Secure Boot Version */".to_string(),
            },
            (self.flags as QtiFlags).debug()
        )?;
        writeln!(
            f,
            "Use JTAG ID: {}",
            (self.flags as QtiFlags).in_use_hw_id()
        )?;
        if self.major_version > 0 {
            writeln!(
                f,
                "Use Application ID: {}",
                !(self.flags as QtiFlags).model_id_independent()
            )?;
        }
        writeln!(
            f,
            "SoC Hardware Versions: [\n{}",
            self.soc_version
                .into_iter()
                .filter(|v| *v != 0)
                .map(|v| format!("        {:#010x},", v))
                .chain(std::iter::once("    ]".to_string()))
                .collect::<Vec<String>>()
                .join("\n")
        )?;
        writeln!(
            f,
            "Serial Numbers: [\n{}",
            self.multi_serial_numbers
                .into_iter()
                .filter(|v| *v != 0)
                .map(|v| format!("        {:#010x},", v))
                .chain(std::iter::once("    ]".to_string()))
                .collect::<Vec<String>>()
                .join("\n")
        )?;
        writeln!(
            f,
            "Root Certificate Index in MRC (Multiple Root Certificate): {}",
            self.root_cert_index as u32
        )?;
        write!(
            f,
            "Anti-Rollback Version: {:#010x}",
            self.anti_rollback_version as u32
        )
    }
}

impl From<u32> for QtiFlags {
    fn from(value: u32) -> Self {
        Self { 0: value }
    }
}

impl From<QtiFlags> for u32 {
    fn from(value: QtiFlags) -> Self {
        value.0
    }
}

impl From<[u8; 120]> for Metadata {
    fn from(value: [u8; 120]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<Metadata> for [u8; 120] {
    fn from(value: Metadata) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl ByteRead for Metadata {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            From::<[u8; std::mem::size_of::<Self>()]>::from(
                buffer
                    .current()
                    .get(0..std::mem::size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            ),
            std::mem::size_of::<Self>(),
        ))
    }
}
