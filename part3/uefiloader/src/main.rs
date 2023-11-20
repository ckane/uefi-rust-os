#![no_main]
#![no_std]

mod cfg_table_type;
mod kernel_args;
mod identity_acpi_handler;
mod console;

// Use the abstracted log interface for console output
use log::{error, info, warn};

use acpi::AcpiTables;
use acpi::mcfg::PciConfigRegions;

// Import a bunch of commonly-used UEFI symbols exported by the crate
use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;
use uefi::table::boot::ScopedProtocol;

use crate::console::Console;
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

// Maximum Width & Height values for screen resolution
const MAX_WIDTH: usize = 1920;
const MAX_HEIGHT: usize = 1080;

fn get_gfx_handle(st: &SystemTable<Boot>) -> ScopedProtocol<GraphicsOutput> {
    st.boot_services()
        .get_handle_for_protocol::<GraphicsOutput>()
        .and_then(|x| {
            st.boot_services()
                .open_protocol_exclusive::<GraphicsOutput>(x)
        })
        .unwrap()
}

fn init_fb(st: &SystemTable<Boot>) {
    let mut gfx = get_gfx_handle(st);

    // Start with setting the current "largest" mode to the first mode
    let mut curmode = 0u32;

    // Initialize both the largest width/height so far to 0, so they'll be overwritten
    // by whatever the first mode returns
    let mut curwide = 0;
    let mut curhigh = 0;

    // Iterate across all the modes - if a mode that is within our bounds, but larger than
    // the previous largest mode is identified, then set that as the new preferred mode
    for (i, m) in gfx.modes().enumerate() {
        let mode = m.info();
        // Only want 24-bit RGB modes
        if mode.pixel_format() == uefi::proto::console::gop::PixelFormat::Rgb
            || mode.pixel_format() == uefi::proto::console::gop::PixelFormat::Bgr
        {
            let (xc, yc) = mode.resolution(); // Populate temp xc/yc with the X/Y of the video mode
            if ((xc > curwide) && (xc <= MAX_WIDTH)) || ((yc > curhigh) && (yc <= MAX_HEIGHT)) {
                // If it more closely matches our constraints than any mode prior, select it
                // as the new "preferred mode"
                curmode = i as u32;
                curwide = xc;
                curhigh = yc;
            }
        }
    }

    // At the end of the loop, curmode contains the numeric index of the best-fit mode
    let newmode = gfx.query_mode(curmode).unwrap();

    // This sets the graphics mode
    gfx.set_mode(&newmode).unwrap();

    /*// Once the graphics mode is set, we can get the Framebuffer pointer and its size, in bytes
    let fbptr = gfx.frame_buffer().as_mut_ptr();
    let fbsize = gfx.frame_buffer().size();

    // We can also query additional details about the video mode that will be helpful for informing
    // framebuffer drawing operations
    let mode_info = gfx.current_mode_info().clone();
    let fbx = mode_info.resolution().0; // The display width
    let fby = mode_info.resolution().1; // The display height
    let fbpf = mode_info.pixel_format(); // The pixel format of the chosen display

    // Get the bitmask details for the color planes (Which may be useful)
    let masks = if let Some(pf) = mode_info.pixel_bitmask() {
        (pf.red, pf.green, pf.blue)
    } else {
        (0, 0, 0)
    };

    // The stride is how many bytes are in a row, which may be different than simply X*4 due to
    // hardware constraints
    let fbstride = mode_info.stride();

    // Render a small pixel to the screen at (100,100)
    let fbref = unsafe { core::slice::from_raw_parts_mut::<u32>(fbptr as *mut u32, fbsize/4) };
    fbref[fbstride/4 * 100 + 100] = 0x0000ffff;
    */
}

fn draw_square(st: &SystemTable<Boot>) {
    let mut gfx = get_gfx_handle(st);

    let mode_info = gfx.current_mode_info();

    // Lets draw a 2x2 square on the screen
    let top = 100 * mode_info.stride();
    let left = 100;
    let mut fb = gfx.frame_buffer();
    const WHITE_PIXEL: [u8; 3] = [0xffu8, 0xffu8, 0xffu8];
    unsafe {
        for i in 0..100 {
            fb.write_value((top + left + i) * 4, WHITE_PIXEL);
            fb.write_value((top + left + i*mode_info.stride()) * 4, WHITE_PIXEL);
            fb.write_value((top + left + 100*mode_info.stride() + i) * 4, WHITE_PIXEL);
            fb.write_value((top + left + i*mode_info.stride() + 100) * 4, WHITE_PIXEL);
        }
    };
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

    wait_for_keypress(&mut system_table).unwrap();

    init_fb(&mut system_table);
    draw_square(&mut system_table);

    let mut con = Console::new_from_uefi_gfx(get_gfx_handle(&mut system_table));

    // Write "Hello from Graphics" to the upper-left corner of the screen
    let _ = con.write_str("Hello from Graphics", 0, 9);

    // Wait for another keypress after setting the mode, so we can see it worked
    wait_for_keypress(&mut system_table).unwrap();

    // Tell the UEFI firmware we exited without error
    Status::SUCCESS
}
