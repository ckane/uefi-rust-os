#![no_main]
#![no_std]

// Use the abstracted log interface for console output
use log::{error, info, warn};

// Import a bunch of commonly-used UEFI symbols exported by the crate
use uefi::prelude::*;

// Tell the uefi crate that this function will be our entrypoint
#[entry]
// Declare "hello_main" to accept two arguments, and use the type definitions provided by uefi
fn hello_main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // In order to use any of the services (input, output, etc...), they need to be manually
    // initialized by the UEFI program
    uefi_services::init(&mut system_table).unwrap();

    info!("This is an INFO message");
    warn!("This is a WARN message");
    error!("This is an ERROR message");
    info!("Image Handle: {:#018x}", image_handle.as_ptr() as usize);
    info!("System Table: {:#018x}", core::ptr::addr_of!(system_table) as usize);
    info!(
        "UEFI Revision: {}.{}",
        system_table.uefi_revision().major(),
        system_table.uefi_revision().minor()
    );

    // Pause for 10 seconds
    system_table.boot_services().stall(10_000_000);

    // Tell the UEFI firmware we exited without error
    Status::SUCCESS
}
