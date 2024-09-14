use core::format_args;
use uefi::{guid, Guid};

#[derive(Debug)]
pub struct CfgTableType(uefi::Guid);

pub const UEFI_MEMORY_ATTRIBUTES_TABLE: Guid = guid!("dcfa911d-26eb-469f-a220-38b7dc461220");

impl From<Guid> for CfgTableType {
    fn from(guid: Guid) -> Self {
        Self(guid)
    }
}

impl core::fmt::Display for CfgTableType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        match self.0 {
            uefi::table::cfg::ACPI2_GUID => f.write_str("ACPI2"),
            uefi::table::cfg::ACPI_GUID => f.write_str("ACPI1"),
            uefi::table::cfg::DEBUG_IMAGE_INFO_GUID => f.write_str("Debug Image"),
            uefi::table::cfg::DXE_SERVICES_GUID => f.write_str("DXE Services"),
            uefi::table::cfg::ESRT_GUID => f.write_str("EFI System Resources"),
            uefi::table::cfg::HAND_OFF_BLOCK_LIST_GUID => f.write_str("Hand-off Block List"),
            uefi::table::cfg::LZMA_COMPRESS_GUID => f.write_str("LZMA Compressed filesystem"),
            uefi::table::cfg::MEMORY_STATUS_CODE_RECORD_GUID => f.write_str("Hand-off Status Code"),
            uefi::table::cfg::MEMORY_TYPE_INFORMATION_GUID => {
                f.write_str("Memory Type Information")
            }
            uefi::table::cfg::PROPERTIES_TABLE_GUID => f.write_str("Properties Table"),
            uefi::table::cfg::SMBIOS3_GUID => f.write_str("SMBIOS3"),
            uefi::table::cfg::SMBIOS_GUID => f.write_str("SMBIOS1"),
            uefi::table::cfg::TIANO_COMPRESS_GUID => f.write_str("Tiano compressed filesystem"),
            UEFI_MEMORY_ATTRIBUTES_TABLE => f.write_str("Memory Attributes"),
            x => f.write_fmt(format_args!("{}", x)),
        }
    }
} // TODO: finish this
