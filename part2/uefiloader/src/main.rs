#![no_main]
#![no_std]

mod cfg_table_type;
mod kernel_args;
mod identity_acpi_handler;

// Use the abstracted log interface for console output
use log::{error, info, warn};

use acpi::AcpiTables;
use acpi::mcfg::PciConfigRegions;

// Import a bunch of commonly-used UEFI symbols exported by the crate
use uefi::prelude::*;

use crate::kernel_args::{KernelArgs, OSMemEntry};
use crate::identity_acpi_handler::IdentityAcpiHandler;

fn wait_for_keypress(st: &mut SystemTable<Boot>) -> uefi::Result {
    info!("Press a key to contine...");
    st.stdin().reset(true)?;

    let mut key_press_event = unsafe { [st.stdin().wait_for_key_event().unsafe_clone()] };
    st.boot_services().wait_for_event(&mut key_press_event).unwrap();
    Ok(())
}

impl From<&uefi::table::boot::MemoryDescriptor> for OSMemEntry {
    fn from(mdesc: &uefi::table::boot::MemoryDescriptor) -> OSMemEntry {
        OSMemEntry {
            ty: mdesc.ty,
            base: mdesc.phys_start as usize,
            pages: mdesc.page_count as usize,
            att: mdesc.att,
        }
    }
}

fn get_mm(st: &SystemTable<Boot>) -> (*mut OSMemEntry, usize) {
    // Allocate a buffer for the memory map
    let mm_size = st.boot_services().memory_map_size();

    // Make it a few entries bigger than the size that was given
    let mm_bytes = mm_size.map_size + (mm_size.entry_size * 5);
    let mm_buffer = st.boot_services().allocate_pool(
        uefi::table::boot::MemoryType::BOOT_SERVICES_DATA,
        mm_bytes,
    ).unwrap();

    // Convert from *mut u8 to &mut [u8]
    let mm_ref = unsafe { core::slice::from_raw_parts_mut(mm_buffer, mm_bytes) };

    // Populate the memory map from UEFI into this new buffer
    let mdesc = st.boot_services().memory_map(mm_ref).unwrap();

    // Allocate a new buffer that is guaranteed to fit the same number of OSMemEntry items
    // that we have MemoryDescriptor items for
    let mem_entries = (mm_bytes / mm_size.entry_size) + 1;
    let mementry_ptr = st.boot_services().allocate_pool(
        uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
        mem_entries * core::mem::size_of::<OSMemEntry>(),
    ).unwrap() as *mut OSMemEntry;

    // Convert it from a *mut OSMemEntry to a &mut [OSMemEntry] to make it safer to index
    let mementries = unsafe { core::slice::from_raw_parts_mut::<OSMemEntry>(mementry_ptr, mem_entries) };

    // Loop across the MemoryDescriptors and make a copy of each one into the &mut [OSMemEntry]
    // slice
    let mut num_entries = 0;
    for (i, e) in mdesc.entries().enumerate() {
        mementries[i] = e.into(); // Use the translation code that we wrote
        num_entries += 1;
    };
    (mementry_ptr, num_entries)
}

// Tell the uefi crate that this function will be our entrypoint
#[entry]
// Declare "hello_main" to accept two arguments, and use the type definitions provided by uefi
fn hello_main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // In order to use any of the services (input, output, etc...), they need to be manually
    // initialized by the UEFI program
    uefi_services::init(&mut system_table).unwrap();

    info!("Image Handle: {:#018x}", image_handle.as_ptr() as usize);
    info!("System Table: {:#018x}", core::ptr::addr_of!(system_table) as usize);
    info!(
        "UEFI Revision: {}.{}",
        system_table.uefi_revision().major(),
        system_table.uefi_revision().minor()
    );

    let mut karg = KernelArgs::default();
    info!("Empty karg: {:?}", karg);
    karg.populate_from_cfg_table(system_table.config_table());
    info!("Populated karg: {:?}", karg);

    let ih = IdentityAcpiHandler; // Create a new IdentityAcpiHandler
    let acpi_tables = unsafe { AcpiTables::from_rsdp(ih, karg.get_acpi().0 as usize) }.unwrap();
    info!("ACPI Revision: {}", acpi_tables.revision);

    let pcie_cfg = PciConfigRegions::new(&acpi_tables).unwrap();
    for sg in 0u16..=65535u16 {
        if let Some(addr) = pcie_cfg.physical_address(sg, 0, 0, 0) {
            karg.set_pcie(addr as *mut core::ffi::c_void);
            break;
        }
    }
    info!("karg after PCIe: {:?}", karg);

    wait_for_keypress(&mut system_table).unwrap();

    let (mm_ptr, count) = get_mm(&system_table);
    karg.set_memmap(mm_ptr, count);

    info!("Got memory");
    info!("karg after MemMap: {:?}", karg);

    // Tell the UEFI firmware we exited without error
    wait_for_keypress(&mut system_table).unwrap();
    Status::SUCCESS
}
