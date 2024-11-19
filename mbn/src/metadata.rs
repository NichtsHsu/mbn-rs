use std::mem::size_of;

use crate::{
    byte_read::{ByteRead, ByteReader},
    error::ParseError,
};

/// The [`flags`](MetadataLen120::flags) field of [`MetadataLen120`].
///
/// See [`QtiFlagsV6Builder`] for build a [`QtiFlagsV6`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QtiFlagsV6(pub u32);

/// Builder for [`QtiFlagsV6`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct QtiFlagsV6Builder(u32);

/// The [`flags`](MetadataLen224::flags) field of [`MetadataLen224`].
///
/// This version of QTI flags use `0b01` as `false` and `0b10` as `true`,
/// so illegal values may appear in each field.
///
/// See [`QtiFlagsV7Builder`] for build a [`QtiFlagsV7`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QtiFlagsV7(pub u32);

/// Builder for [`QtiFlagsV7`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct QtiFlagsV7Builder(u32);

/// The common metadata representation.
///
/// Only [`HashTableSegment`](crate::HashTableSegment)
/// containing [`MbnHeaderV7`](crate::MbnHeaderV7) has common metadata.
#[repr(packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommonMetadata {
    /// Metadata major version.
    pub major_version: u32,
    /// Metadata minor version.
    pub minor_version: u32,
    /// A 32-bit software type value of the image which specifies the signed image.
    pub software_id: u32,
    /// Required for a TZ application.
    pub app_id: u32,
    /// Hash algorithm used for hash table.
    ///
    /// * 2: SHA256
    /// * 3: SHA384
    pub hash_table_algorithm: u32,
    /// Measurement Register Target.
    ///
    /// * 0: None
    /// * 1: Hardware Measurement Register #1
    /// * 2: Hardware Measurement Register #2
    /// * 3: Firmware Measurement Register #1
    /// * 4: Firmware Measurement Register #2
    /// * 5: Firmware Measurement Register #3
    /// * 6: Firmware Measurement Register #4
    pub measurement_register: u32,
}

/// The 120 bytes QTI metadata and OEM metadata representation.
///
/// Only [`HashTableSegment`](crate::HashTableSegment)
/// containing [`MbnHeaderV6`](crate::MbnHeaderV6) has 120 bytes metadata.
#[repr(packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetadataLen120 {
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
    /// See [`QtiFlagsV6`].
    pub flags: QtiFlagsV6,
    /// Contains up to 12 unique SoC hardware version values.
    pub soc_version: [u32; 12],
    /// Contains up to 8 serial numbers.
    pub multi_serial_numbers: [u32; 8],
    /// The active root certificate index in MRC (Multiple Root Certificate).
    pub root_cert_index: u32,
    /// Anti-rollback version specifies the minimum supported version.
    pub anti_rollback_version: u32,
}

/// The 224 bytes QTI metadata and OEM metadata representation.
///
/// Only [`HashTableSegment`](crate::HashTableSegment)
/// containing [`MbnHeaderV7`](crate::MbnHeaderV7) has 224 bytes metadata.
#[repr(packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataLen224 {
    /// Metadata major version.
    pub major_version: u32,
    /// Metadata minor version.
    pub minor_version: u32,
    /// Anti-rollback version specifies the minimum supported version.
    pub anti_rollback_version: u32,
    /// The active root certificate index in MRC (Multiple Root Certificate).
    pub root_cert_index: u32,
    /// Contains up to 12 unique SoC hardware version values.
    pub soc_version: [u32; 12],
    /// SoC feature ID.
    pub feature_id: u32,
    /// The hardware ID is composed of JTAG ID.
    pub hardware_id: u32,
    /// Contains up to 8 serial numbers.
    pub multi_serial_numbers: [u64; 8],
    /// A 32-bit value served as CASS account ID for the OEM.
    pub oem_id: u32,
    /// Model ID prevents misuse of images across various models.
    pub model_id: u32,
    /// OEM lifecycle state.
    ///
    /// * `0x200000000`: Development
    /// * `0xD00000000`: Production
    pub oem_lifecycle_state: u64,
    /// Hash algorithm used for OEM root certificate.
    ///
    /// * 0: N/A
    /// * 2: SHA256
    /// * 3: SHA384
    pub oem_root_cert_hash_algorithm: u32,
    /// OEM root certificate hash value.
    ///
    /// Use the last 32 bytes when [`oem_root_cert_hash_algorithm`](MetadataLen224::oem_root_cert_hash_algorithm)
    /// is 2 (SHA256) or the last 48 bytes when it is 3 (SHA384).
    pub oem_root_cert_hash: [u8; 64],
    /// See [`QtiFlagsV7`].
    pub flags: QtiFlagsV7,
}

/// The QTI metadata and OEM metadata representation.
///
/// Only [`HashTableSegment`](crate::HashTableSegment)
/// containing MBN header with version greater than 6 has this metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metadata {
    Len120(MetadataLen120),
    Len224(MetadataLen224),
}

impl QtiFlagsV6 {
    /// RoT (Root of Trust) enablement.
    pub fn rot_en(&self) -> bool {
        self.0 & 1 != 0
    }

    /// Using [`MetadataLen120::soc_version`] in image signing.
    pub fn use_soc_hw_version(&self) -> bool {
        self.0 & (1 << 1) != 0
    }

    /// Using serial number in image signing.
    pub fn use_serial_number(&self) -> bool {
        self.0 & (1 << 2) != 0
    }

    /// Using [`MetadataLen120::oem_id`] in image signing if **`false`**.
    pub fn oem_id_independent(&self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// Enables revocation and activation in MRC (Multiple Root Certificate).
    ///
    /// * 0: Disable
    /// * 1: Enable
    /// * 2: Enable with serial number binding provided in the [`MetadataLen120::multi_serial_numbers`] field.
    pub fn root_revoke_activate_enable(&self) -> u8 {
        ((self.0 >> 4) & 0b11) as u8
    }

    /// Enables UIE (Unified Image Encryption) key switch.
    ///
    /// * 0: Disable
    /// * 1: Enable
    /// * 2: Enable with serial number binding provided in the [`MetadataLen120::multi_serial_numbers`] field.
    pub fn uie_key_switch_enable(&self) -> u8 {
        ((self.0 >> 6) & 0b11) as u8
    }

    /// JTAG debug.
    ///
    /// * 0: Nothing is written to the one-time debug override registers.
    /// * 1: `0` is to be written to the one-time debug override registers.
    /// * 2: `1` is to be written to the one-time debug override registers.
    pub fn debug(&self) -> u8 {
        ((self.0 >> 8) & 0b11) as u8
    }

    /// Using [`MetadataLen120::hardware_id`] in image signing.
    ///
    /// Valid only when [`MetadataLen120::major_version`] is greater than 0.
    pub fn use_hw_id(&self) -> bool {
        self.0 & (1 << 10) != 0
    }

    /// Using [`MetadataLen120::model_id`] in image signing if **`false`**.
    ///
    /// Valid only when [`MetadataLen120::major_version`] is greater than 0.
    pub fn model_id_independent(&self) -> bool {
        self.0 & (1 << 11) != 0
    }
}

impl QtiFlagsV6Builder {
    fn set_bit(&mut self, bit: u8) {
        self.0 |= 1 << bit;
    }

    fn clear_bit(&mut self, bit: u8) {
        self.0 &= !(1 << bit);
    }

    fn set_value(&mut self, start: u8, end: u8, value: u8) {
        (start..end).for_each(|x| self.clear_bit(x));
        let mask = (1 << (end - start)) - 1;
        self.0 |= (value as u32 & mask) << start;
    }

    /// Create a new builder.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new builder based on [`QtiFlagsV6`].
    pub fn with(flags: QtiFlagsV6) -> Self {
        Self(flags.0)
    }

    /// Build [`QtiFlagsV6`].
    pub fn build(self) -> QtiFlagsV6 {
        QtiFlagsV6(self.0)
    }

    /// Set [`rot_en`](QtiFlagsV6::rot_en()) bit.
    pub fn rot_en(&mut self) {
        self.set_bit(0);
    }

    /// Set [`use_soc_hw_version`](QtiFlagsV6::use_soc_hw_version()) bit.
    pub fn use_soc_hw_version(&mut self) {
        self.set_bit(1);
    }

    /// Set [`use_serial_number`](QtiFlagsV6::use_serial_number) bit.
    pub fn use_use_serial_number(&mut self) {
        self.set_bit(2);
    }

    /// Set [`oem_id_independent`](QtiFlagsV6::oem_id_independent()) bit.
    pub fn oem_id_independent(&mut self) {
        self.set_bit(3);
    }

    /// Set [`root_revoke_activate_enable`](QtiFlagsV6::root_revoke_activate_enable()) value.
    pub fn root_revoke_activate_enable(&mut self, value: u8) {
        self.set_value(4, 6, value);
    }

    /// Set [`uie_key_switch_enable`](QtiFlagsV6::uie_key_switch_enable()) value.
    pub fn uie_key_switch_enable(&mut self, value: u8) {
        self.set_value(6, 8, value);
    }

    /// Set [`debug`](QtiFlagsV6::debug()) value.
    pub fn debug(&mut self, value: u8) {
        self.set_value(8, 10, value);
    }

    /// Set [`use_hw_id`](QtiFlagsV6::use_hw_id()) bit.
    pub fn use_hw_id(&mut self) {
        self.set_bit(10);
    }

    /// Set [`model_id_independent`](QtiFlagsV6::model_id_independent()) bit.
    pub fn model_id_independent(&mut self) {
        self.set_bit(11);
    }
}

impl QtiFlagsV7 {
    /// Using [`MetadataLen224::soc_version`] in image signing.
    pub fn use_soc_hw_version(&self) -> Result<bool, u8> {
        match self.0 & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using [`MetadataLen224::feature_id`] in image signing.
    pub fn use_feature_id(&self) -> Result<bool, u8> {
        match (self.0 >> 2) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using [`MetadataLen224::hardware_id`] in image signing.
    pub fn use_hw_id(&self) -> Result<bool, u8> {
        match (self.0 >> 4) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using serial number in image signing.
    pub fn use_serial_number(&self) -> Result<bool, u8> {
        match (self.0 >> 6) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using [`MetadataLen224::oem_id`] in image signing.
    pub fn use_oem_id(&self) -> Result<bool, u8> {
        match (self.0 >> 8) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using [`MetadataLen224::model_id`] in image signing.
    pub fn use_model_id(&self) -> Result<bool, u8> {
        match (self.0 >> 10) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using SoC lifecycle state in image signing.
    pub fn use_soc_lifecycle_state(&self) -> Result<bool, u8> {
        match (self.0 >> 12) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using [`MetadataLen224::oem_lifecycle_state`] in image signing.
    pub fn use_oem_lifecycle_state(&self) -> Result<bool, u8> {
        match (self.0 >> 14) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// Using [`MetadataLen224::oem_root_cert_hash`] in image signing.
    pub fn use_oem_root_cert_hash(&self) -> Result<bool, u8> {
        match (self.0 >> 16) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// JTAG debug.
    ///
    /// * `false`: Nothing is written to the one-time debug override registers.
    /// * `true`: `0` is to be written to the one-time debug override registers.
    ///
    /// *It seems that `1` is no longer supported? Not clear.*
    pub fn debug(&self) -> Result<bool, u8> {
        match (self.0 >> 18) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }

    /// RoT (Root of Trust) enablement.
    pub fn rot_en(&self) -> Result<bool, u8> {
        match (self.0 >> 20) & 0b11 {
            0b01 => Ok(false),
            0b10 => Ok(true),
            unknown => Err(unknown as u8),
        }
    }
}

impl QtiFlagsV7Builder {
    fn clear_bit(&mut self, bit: u8) {
        self.0 &= !(1 << bit);
    }

    fn set_true(&mut self, start: u8) {
        (start..start + 2).for_each(|x| self.clear_bit(x));
        self.0 |= 0b10 << start;
    }

    /// Create a new builder.
    pub fn new() -> Self {
        Self(0b0101010101010101010101)
    }

    /// Create a new builder based on [`QtiFlagsV7`].
    pub fn with(flags: QtiFlagsV7) -> Self {
        Self(flags.0)
    }

    /// Build [`QtiFlagsV7`].
    pub fn build(self) -> QtiFlagsV7 {
        QtiFlagsV7(self.0)
    }

    /// Set [`use_soc_hw_version`](QtiFlagsV7::use_soc_hw_version()) to `true`.
    pub fn use_soc_hw_version(&mut self) {
        self.set_true(0);
    }

    /// Set [`use_feature_id`](QtiFlagsV7::use_feature_id()) to `true`.
    pub fn use_feature_id(&mut self) {
        self.set_true(2);
    }

    /// Set [`use_hw_id`](QtiFlagsV7::use_hw_id()) to `true`.
    pub fn use_hw_id(&mut self) {
        self.set_true(4);
    }

    /// Set [`use_serial_number`](QtiFlagsV7::use_serial_number()) to `true`.
    pub fn use_serial_number(&mut self) {
        self.set_true(6);
    }

    /// Set [`use_oem_id`](QtiFlagsV7::use_oem_id()) to `true`.
    pub fn use_oem_id(&mut self) {
        self.set_true(8);
    }

    /// Set [`use_model_id`](QtiFlagsV7::use_model_id()) to `true`.
    pub fn use_model_id(&mut self) {
        self.set_true(10);
    }

    /// Set [`use_soc_lifecycle_state`](QtiFlagsV7::use_soc_lifecycle_state()) to `true`.
    pub fn use_soc_lifecycle_state(&mut self) {
        self.set_true(12);
    }

    /// Set [`use_oem_lifecycle_state`](QtiFlagsV7::use_oem_lifecycle_state()) to `true`.
    pub fn use_oem_lifecycle_state(&mut self) {
        self.set_true(14);
    }

    /// Set [`use_oem_root_cert_hash`](QtiFlagsV7::use_oem_root_cert_hash()) to `true`.
    pub fn use_oem_root_cert_hash(&mut self) {
        self.set_true(16);
    }

    /// Set [`debug`](QtiFlagsV7::debug()) to `true`.
    pub fn debug(&mut self) {
        self.set_true(18);
    }

    /// Set [`rot_en`](QtiFlagsV7::rot_en()) to `true`.
    pub fn rot_en(&mut self) {
        self.set_true(20);
    }
}

impl CommonMetadata {
    /// Convert itself to a 24 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        unsafe { &*(self as *const _ as *const _) }
    }
}

impl MetadataLen120 {
    /// Convert itself to a 120 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        unsafe { &*(self as *const _ as *const _) }
    }
}

impl MetadataLen224 {
    /// Convert itself to a 224 bytes slice without copy.
    pub fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        unsafe { &*(self as *const _ as *const _) }
    }
}

impl Metadata {
    /// Convert itself to a slice without copy.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Metadata::Len120(metadata) => metadata.as_bytes(),
            Metadata::Len224(metadata) => metadata.as_bytes(),
        }
    }
}

impl Default for MetadataLen224 {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl Default for QtiFlagsV7 {
    fn default() -> Self {
        Self(0b0101010101010101010101)
    }
}

impl std::fmt::Display for CommonMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Major Version: {}", { self.major_version })?;
        writeln!(f, "Minor Version: {}", { self.minor_version })?;
        writeln!(f, "Software ID: {:#010x}", { self.software_id })?;
        writeln!(f, "Application ID: {:#010x}", { self.app_id })?;
        writeln!(
            f,
            "Hash Table Algorithm: {} ({:#x})",
            match self.hash_table_algorithm {
                2 => "SHA256",
                3 => "SHA384",
                _ => "/* Unknown */",
            },
            { self.hash_table_algorithm }
        )?;
        write!(
            f,
            "Measurement Register: {} ({:#x})",
            match self.measurement_register {
                0 => "None",
                1 => "Hardware Measurement Register #1",
                2 => "Hardware Measurement Register #2",
                3 => "Firmware Measurement Register #1",
                4 => "Firmware Measurement Register #2",
                5 => "Firmware Measurement Register #3",
                6 => "Firmware Measurement Register #4",
                _ => "/* Unknown */",
            },
            { self.measurement_register }
        )
    }
}

impl std::fmt::Display for MetadataLen120 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Major Version: {}", { self.major_version })?;
        writeln!(f, "Minor Version: {}", { self.minor_version })?;
        writeln!(f, "Software ID: {:#010x}", { self.software_id })?;
        writeln!(f, "JTAG ID: {:#010x}", { self.hardware_id })?;
        writeln!(f, "OEM ID: {:#010x}", { self.oem_id })?;
        writeln!(f, "Product ID: {:#010x}", { self.model_id })?;
        writeln!(f, "Application ID: {:#010x}", { self.app_id })?;
        writeln!(f, "Flags: {:#034b}", { self.flags.0 })?;
        writeln!(f, "    RoT (Root of Trust): {}", ({ self.flags }).rot_en())?;
        writeln!(
            f,
            "    Use SoC Hardware Versions: {}",
            ({ self.flags }).use_soc_hw_version()
        )?;
        writeln!(
            f,
            "    Use Serial Numbers: {}",
            ({ self.flags }).use_serial_number()
        )?;
        writeln!(
            f,
            "    Use OEM ID: {}",
            !({ self.flags }).oem_id_independent()
        )?;
        writeln!(
            f,
            "    Revocation and Activation in MRC (Multiple Root Certificate): {} ({:#x})",
            ({ self.flags }).root_revoke_activate_enable() > 0,
            ({ self.flags }).root_revoke_activate_enable()
        )?;
        writeln!(
            f,
            "    UIE (Unified Image Encryption) Key Switch: {} ({:#x})",
            ({ self.flags }).uie_key_switch_enable() > 0,
            ({ self.flags }).uie_key_switch_enable()
        )?;
        writeln!(
            f,
            "    JTAG Debug: {} ({:#x})",
            match ({ self.flags }).debug() {
                0 => "Nop",
                1 => "Disabled",
                2 => "Enabled",
                _ => "/* Unknown */",
            },
            ({ self.flags }).debug()
        )?;
        writeln!(f, "    Use JTAG ID: {}", ({ self.flags }).use_hw_id())?;
        if self.major_version > 0 {
            writeln!(
                f,
                "    Use Product ID: {}",
                !({ self.flags }).model_id_independent()
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
            { self.root_cert_index }
        )?;
        write!(f, "Anti-Rollback Version: {:#x}", {
            self.anti_rollback_version
        })
    }
}

impl std::fmt::Display for MetadataLen224 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Major Version: {}", { self.major_version })?;
        writeln!(f, "Minor Version: {}", { self.minor_version })?;
        writeln!(f, "Anti-Rollback Version: {:#x}", {
            self.anti_rollback_version
        })?;
        writeln!(
            f,
            "Root Certificate Index in MRC (Multiple Root Certificate): {}",
            { self.root_cert_index }
        )?;
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
        writeln!(f, "SoC Feature ID: {:#010x}", { self.feature_id })?;
        writeln!(f, "JTAG ID: {:#010x}", { self.hardware_id })?;
        writeln!(
            f,
            "Serial Numbers: [\n{}",
            self.multi_serial_numbers
                .into_iter()
                .filter(|v| *v != 0)
                .map(|v| format!("        {:#018x},", v))
                .chain(std::iter::once("    ]".to_string()))
                .collect::<Vec<String>>()
                .join("\n")
        )?;
        writeln!(f, "OEM ID: {:#010x}", { self.oem_id })?;
        writeln!(f, "Product ID: {:#010x}", { self.model_id })?;
        writeln!(
            f,
            "OEM Lifecycle State: {} ({:#018x})",
            match self.oem_lifecycle_state {
                0x200000000 => "Development",
                0xD00000000 => "Production",
                _ => "/* Unknown */",
            },
            { self.oem_lifecycle_state }
        )?;
        writeln!(
            f,
            "OEM Root Certificate Hash Algorithm: {} ({:#x})",
            match self.oem_root_cert_hash_algorithm {
                0 => "N/A",
                2 => "SHA256",
                3 => "SHA384",
                _ => "/* Unknown */",
            },
            { self.oem_root_cert_hash_algorithm }
        )?;
        if self.oem_root_cert_hash_algorithm != 0 {
            writeln!(
                f,
                "OEM Root Certificate Hash: {}",
                match self.oem_root_cert_hash_algorithm {
                    2 => &self.oem_root_cert_hash[32..],
                    3 => &self.oem_root_cert_hash[24..],
                    _ => &self.oem_root_cert_hash,
                }
                .iter()
                .fold(String::from("0x"), |s, byte| s + &format!("{:02x}", byte)),
            )?;
        }
        writeln!(f, "Flags: {:#034b}", { self.flags.0 })?;
        writeln!(
            f,
            "    Use SoC Hardware Versions: {}",
            match ({ self.flags }).use_soc_hw_version() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use Feature ID: {}",
            match ({ self.flags }).use_feature_id() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use JTAG ID: {}",
            match ({ self.flags }).use_hw_id() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use Serial Numbers: {}",
            match ({ self.flags }).use_serial_number() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use OEM ID: {}",
            match ({ self.flags }).use_oem_id() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use Product ID: {}",
            match ({ self.flags }).use_model_id() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use SoC Lifecycle State: {}",
            match ({ self.flags }).use_soc_lifecycle_state() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use OEM Lifecycle State: {}",
            match ({ self.flags }).use_oem_lifecycle_state() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    Use OEM Root Certificate Hash: {}",
            match ({ self.flags }).use_oem_root_cert_hash() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        writeln!(
            f,
            "    JTAG Debug: {}",
            match ({ self.flags }).debug() {
                Ok(false) => "Nop (0b01)".to_string(),
                Ok(true) => "Disabled (0b10)".to_string(),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )?;
        write!(
            f,
            "    RoT (Root of Trust): {}",
            match ({ self.flags }).rot_en() {
                Ok(v) => format!("{}", v),
                Err(v) => format!("/* Unknown */ ({:#04b})", v),
            }
        )
    }
}

impl std::fmt::Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Metadata::Len120(metadata) => metadata.fmt(f),
            Metadata::Len224(metadata) => metadata.fmt(f),
        }
    }
}

impl From<u32> for QtiFlagsV6 {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<QtiFlagsV6> for u32 {
    fn from(value: QtiFlagsV6) -> Self {
        value.0
    }
}

impl From<u32> for QtiFlagsV7 {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<QtiFlagsV7> for u32 {
    fn from(value: QtiFlagsV7) -> Self {
        value.0
    }
}

impl From<[u8; size_of::<Self>()]> for CommonMetadata {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<CommonMetadata> for [u8; 24] {
    fn from(value: CommonMetadata) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl ByteRead for CommonMetadata {
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

impl From<[u8; size_of::<Self>()]> for MetadataLen120 {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MetadataLen120> for [u8; 120] {
    fn from(value: MetadataLen120) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl ByteRead for MetadataLen120 {
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

impl From<[u8; size_of::<Self>()]> for MetadataLen224 {
    fn from(value: [u8; size_of::<Self>()]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<MetadataLen224> for [u8; 224] {
    fn from(value: MetadataLen224) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl ByteRead for MetadataLen224 {
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
