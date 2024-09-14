use crate::framebuffer::FrameBuffer;
use core::ffi::c_void;
use uefi::table::cfg::{ConfigTableEntry, ACPI2_GUID, ACPI_GUID, SMBIOS3_GUID, SMBIOS_GUID};

#[derive(Debug)]
pub struct OSMemEntry {
    pub ty: uefi::table::boot::MemoryType,
    pub base: usize,
    pub pages: usize,
    pub att: uefi::table::boot::MemoryAttribute,
}

#[derive(Copy, Clone, Debug)]
pub struct KernelArgs {
    /// The physical address of the ACPI RSDP
    acpi_ptr: *const c_void,

    /// The physical address of the SMBIOS table
    smbios_ptr: *const c_void,

    /// The version of the ACPI RSDP pointed at by `self.acpi_ptr`
    acpi_ver: u8,

    /// The version of the SMBIOS table pointed at by `self.smbios_ptr`
    smbios_ver: u8,

    /// The pointer to the PCI Express ECAM Space
    pcie_ptr: *mut c_void,

    /// The pointer to the OSMemEntry list
    memmap_ptr: *mut OSMemEntry,

    /// The number of entries in the slice pointed at by memmap_ptr
    memmap_entries: usize,

    /// The pointer to the kernel base address
    kern_base: *mut c_void,

    /// Number of pages allocated for kernel
    kern_pages: usize,

    /// The FrameBuffer
    fb: FrameBuffer,
}

// Initially populate an empty struct with every value set to 0. We cannot derive this
// because core::ffi::c_void has no Default implementation.
impl Default for KernelArgs {
    fn default() -> Self {
        Self {
            acpi_ptr: core::ptr::null(),
            smbios_ptr: core::ptr::null(),
            acpi_ver: 0,
            smbios_ver: 0,
            pcie_ptr: core::ptr::null_mut(),
            memmap_ptr: core::ptr::null_mut(),
            memmap_entries: 0,
            kern_base: core::ptr::null_mut(),
            kern_pages: 0,
            fb: Default::default(),
        }
    }
}

impl KernelArgs {
    /// Populate the SMBIOS and ACPI pointers/versions from a UEFI Config Table
    pub fn populate_from_cfg_table(&mut self, cfg_tables: &[ConfigTableEntry]) {
        // Iterate across the Config Tables, find the SMBIOS and ACPI tables, and populate their
        // pointers. Multiple versions of the standards could exist in memory, so this process will
        // search the entire table space and favor the highest-version implementation of the ACPI
        // or SMBIO standards, where they are present, and reflect this choice in a separate version
        // field.
        for cfg in cfg_tables {
            match cfg.guid {
                ACPI2_GUID => {
                    if self.acpi_ver < 2 {
                        self.acpi_ver = 2;
                        self.acpi_ptr = cfg.address;
                    }
                }
                ACPI_GUID => {
                    if self.acpi_ver < 1 {
                        self.acpi_ver = 1;
                        self.acpi_ptr = cfg.address;
                    }
                }
                SMBIOS3_GUID => {
                    if self.smbios_ver < 3 {
                        self.smbios_ver = 3;
                        self.smbios_ptr = cfg.address;
                    }
                }
                SMBIOS_GUID => {
                    if self.smbios_ver < 1 {
                        self.smbios_ver = 1;
                        self.smbios_ptr = cfg.address;
                    }
                }
                _ => {}
            }
        }
    }

    /// Returns the ACPI pointer and version as a pair
    pub fn get_acpi(&self) -> (*const c_void, u8) {
        (self.acpi_ptr, self.acpi_ver)
    }

    /// Returns the SMBIOS pointer and version as a pair
    pub fn get_smbios(&self) -> (*const c_void, u8) {
        (self.smbios_ptr, self.smbios_ver)
    }

    /// Sets the PCI Express ECAM pointer
    pub fn set_pcie(&mut self, ptr: *mut c_void) {
        self.pcie_ptr = ptr
    }

    /// Returns the PCI Express ECAM pointer
    pub fn get_pcie(&self) -> *mut c_void {
        self.pcie_ptr
    }

    /// Sets the MemMap pointer and slice length
    pub fn set_memmap(&mut self, ptr: *mut OSMemEntry, entries: usize) {
        self.memmap_ptr = ptr;
        self.memmap_entries = entries;
    }

    /// Returns the MemMap pointer
    pub fn get_memmap(&self) -> *mut OSMemEntry {
        self.memmap_ptr
    }

    /// Returns the number of entries pointed at by the MemMap pointer
    pub fn get_memmap_entries(&self) -> usize {
        self.memmap_entries
    }

    /// Returns the memmap in slice form
    pub fn get_memmap_slice(&self) -> &'static [OSMemEntry] {
        unsafe { core::slice::from_raw_parts(self.memmap_ptr, self.memmap_entries) }
    }

    /// Set the kernel base and number of pages needed for it
    pub fn set_kernaddr(&mut self, base: *mut c_void, pages: usize) {
        self.kern_base = base;
        self.kern_pages = pages;
    }

    /// Get the kernel base address
    pub fn get_kernbase(&self) -> *mut c_void {
        self.kern_base
    }

    /// Get the number of pages kernel occupies
    pub fn get_kernpages(&self) -> usize {
        self.kern_pages
    }

    pub fn set_fb(&mut self, newfb: FrameBuffer) {
        self.fb = newfb;
    }

    pub fn get_fb(&mut self) -> &mut FrameBuffer {
        &mut self.fb
    }
}
