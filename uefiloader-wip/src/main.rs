#![no_main]
#![no_std]

mod cfg_table_type;
mod framebuffer;
mod identity_acpi_handler;
mod kernel_args;
mod paging;

use core::arch::asm;
use core::fmt::Write;
// Use the abstracted log interface for console output
use log::{error, info, warn};

use acpi::mcfg::PciConfigRegions;
use acpi::AcpiTables;

use raw_cpuid::CpuId;

// Import a bunch of commonly-used UEFI symbols exported by the crate
use uefi::prelude::*;

use uefi::proto::console::gop::GraphicsOutput;

use uefi::mem::memory_map::MemoryMap;

use crate::framebuffer::UnsafeFrameBuffer;
use crate::identity_acpi_handler::IdentityAcpiHandler;
use crate::kernel_args::{KernelArgs, OSMemEntry};

impl From<&mut GraphicsOutput> for UnsafeFrameBuffer {
    fn from(gfx: &mut GraphicsOutput) -> UnsafeFrameBuffer {
        let cur_mode = gfx.current_mode_info();
        let mut uefifb = gfx.frame_buffer();
        UnsafeFrameBuffer::new(
            uefifb.as_mut_ptr(),
            uefifb.size(),
            cur_mode.resolution().0,
            cur_mode.resolution().1,
            cur_mode.stride(),
            cur_mode.pixel_format(),
            0,
            0,
            0,
        )
    }
}

fn wait_for_keypress(st: &mut SystemTable<Boot>) -> uefi::Result {
    info!("Press a key to contine...");
    st.stdin().reset(true)?;

    let mut key_press_event = [st.stdin().wait_for_key_event().unwrap()];
    st.boot_services()
        .wait_for_event(&mut key_press_event)
        .unwrap();
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

fn set_mode(st: &SystemTable<Boot>) -> UnsafeFrameBuffer {
    let mut gfx = st
        .boot_services()
        .get_handle_for_protocol::<uefi::proto::console::gop::GraphicsOutput>()
        .and_then(|x| {
            st.boot_services()
                .open_protocol_exclusive::<uefi::proto::console::gop::GraphicsOutput>(x)
        })
        .unwrap();

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
    let newmode = gfx.modes().nth(curmode as usize).unwrap();

    // This sets the graphics mode
    gfx.set_mode(&newmode);

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
    gfx.get_mut().unwrap().into()
}

fn get_mm(st: &SystemTable<Boot>) -> (*mut OSMemEntry, usize) {
    // Allocate a buffer for the memory map
    /*let mm_size = st.boot_services().memory_map_size();

    // Make it a few entries bigger than the size that was given
    let mm_bytes = mm_size.map_size + (mm_size.entry_size * 5);
    let mm_buffer = st
        .boot_services()
        .allocate_pool(uefi::table::boot::MemoryType::BOOT_SERVICES_DATA, mm_bytes)
        .unwrap();

    // Convert from *mut u8 to &mut [u8]
    let mm_ref = unsafe { core::slice::from_raw_parts_mut(mm_buffer, mm_bytes) };*/

    // Populate the memory map from UEFI into this new buffer
    let mdesc = st.boot_services().memory_map(uefi::table::boot::MemoryType::BOOT_SERVICES_DATA).unwrap();

    // Allocate a new buffer that is guaranteed to fit the same number of OSMemEntry items
    // that we have MemoryDescriptor items for
    let mem_entries = mdesc.entries().len();
    let mementry_ptr = st
        .boot_services()
        .allocate_pool(
            uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
            mem_entries * core::mem::size_of::<OSMemEntry>(),
        )
        .unwrap().as_ptr() as *mut OSMemEntry;

    // Convert it from a *mut OSMemEntry to a &mut [OSMemEntry] to make it safer to index
    let mementries =
        unsafe { core::slice::from_raw_parts_mut::<OSMemEntry>(mementry_ptr, mem_entries) };

    // Loop across the MemoryDescriptors and make a copy of each one into the &mut [OSMemEntry]
    // slice
    let mut num_entries = 0;
    for (i, e) in mdesc.entries().enumerate() {
        mementries[i] = e.into(); // Use the translation code that we wrote
        num_entries += 1;
    }
    (mementry_ptr, num_entries)
}

fn ph_type_str(ty: u32) -> &'static str {
    match ty {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474e550 => "GNU_EH_FRAME",
        0x6474e551 => "GNU_STACK",
        0x6474e552 => "GNU_RELRO",
        0x6474e553 => "GNU_PROPERTY",
        _ => "UNSUPPORTED",
    }
}

fn support_huge_pages() -> bool {
    let cpu_id = CpuId::new();

    if let Some(e) = cpu_id.get_extended_processor_and_feature_identifiers() {
        e.has_1gib_pages()
    } else {
        // If it's really really old, it won't even support this CPUID call
        false
    }
}

// Tell the uefi crate that this function will be our entrypoint
#[entry]
// Declare "hello_main" to accept two arguments, and use the type definitions provided by uefi
fn hello_main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // In order to use any of the services (input, output, etc...), they need to be manually
    // initialized by the UEFI program
    uefi::helpers::init().unwrap();

    info!("Image Handle: {:#018x}", image_handle.as_ptr() as usize);
    info!(
        "System Table: {:#018x}",
        core::ptr::addr_of!(system_table) as usize
    );
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
    info!("ACPI Revision: {}", acpi_tables.revision());

    let pcie_cfg = PciConfigRegions::new(&acpi_tables).unwrap();
    for sg in 0u16..=65535u16 {
        if let Some(addr) = pcie_cfg.physical_address(sg, 0, 0, 0) {
            karg.set_pcie(addr as *mut core::ffi::c_void);
            break;
        }
    }
    info!("karg after PCIe: {:?}", karg);

    wait_for_keypress(&mut system_table).unwrap();

    let (mut mm_ptr, mut mm_count) = get_mm(&system_table);
    karg.set_memmap(mm_ptr, mm_count);

    info!("Got memory");
    info!("karg after MemMap: {:?}", karg);

    wait_for_keypress(&mut system_table).unwrap();

    karg.set_fb(set_mode(&system_table));
    let mut karg_clone = karg.clone();
    write!(karg.get_fb(), "karg after framebuffer: {:?}", karg_clone).unwrap();
    karg_clone = karg.clone();
    write!(
        karg.get_fb(),
        "karg after framebuffer, second time: {:?}\n",
        karg_clone
    )
    .unwrap();

    let c = unsafe { system_table.unsafe_clone() };
    let myproto = {
        c.boot_services()
            .open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(image_handle)
            .unwrap()
    };
    let pe_bytes = unsafe {
        core::slice::from_raw_parts(myproto.info().0 as *const u8, myproto.info().1 as usize)
    };
    write!(
        karg.get_fb(),
        "{:02x} {:02x} {:02x} {:02x}\n",
        pe_bytes[0],
        pe_bytes[1],
        pe_bytes[2],
        pe_bytes[3]
    );
    write!(karg.get_fb(), "{:#018x}\n", hello_main as usize);
    let mut kernel_data = None;
    match goblin::pe::PE::parse(pe_bytes) {
        Ok(h) => {
            for section in h.sections {
                let vaddr = h.image_base + section.virtual_address as usize;
                write!(
                    karg.get_fb(),
                    "Section: {:8} {:#018x}\n",
                    section.name().unwrap(),
                    vaddr
                )
                .unwrap();
                if section.name().unwrap() == ".kernel" {
                    let data_bytes = unsafe {
                        core::slice::from_raw_parts(
                            vaddr as *const u8,
                            section.virtual_size as usize,
                        )
                    };
                    write!(
                        karg.get_fb(),
                        "{:02x} {:02x} {:02x} {:02x}\n",
                        data_bytes[0],
                        data_bytes[1],
                        data_bytes[2],
                        data_bytes[3]
                    );
                    kernel_data = Some(data_bytes);
                };
            }
        }
        Err(e) => write!(karg.get_fb(), "Error parsing ELF header: {}", e).unwrap(),
    };

    let mut entaddr = 0;
    if let Some(kbytes) = kernel_data {
        write!(karg.get_fb(), "Kernel data found!\n").unwrap();
        if let Ok(elfdata) = goblin::elf::Elf::parse(kbytes) {
            write!(karg.get_fb(), "Kernel is ELF!\n").unwrap();
            write!(
                karg.get_fb(),
                "Kernel phoff: {:#018x}\n",
                elfdata.header.e_phoff
            )
                .unwrap();
            write!(
                karg.get_fb(),
                "Kernel shoff: {:#018x}\n",
                elfdata.header.e_shoff
            )
                .unwrap();
            write!(
                karg.get_fb(),
                "Kernel entry: {:#018x}\n",
                elfdata.header.e_entry
            )
                .unwrap();
            entaddr = elfdata.header.e_entry;
            let mut bootstrap_pages = 0;
            let mut base_addr = !0;
            let mut max_addr = 0;
            write!(karg.get_fb(), "Program headers: \n").unwrap();
            for (i, ph) in elfdata.program_headers.iter().enumerate() {
                if i >= elfdata.header.e_phnum as usize {
                    break;
                }
                write!(karg.get_fb(), "PH #{:02}: \n", i).unwrap();
                write!(karg.get_fb(), "  Flags({:#010x})\n", ph.p_flags,).unwrap();
                write!(
                    karg.get_fb(),
                    "  TYPE: {} ({:#x})\n",
                    ph_type_str(ph.p_type),
                    ph.p_type
                )
                    .unwrap();
                write!(
                    karg.get_fb(),
                    "  Offs({:#018x}, FileSz({}))\n",
                    ph.p_offset,
                    ph.p_filesz
                )
                    .unwrap();
                write!(
                    karg.get_fb(),
                    "  VA({:#018x}, PA({:#018x}), MemSz({}))\n",
                    ph.p_vaddr,
                    ph.p_paddr,
                    ph.p_memsz
                )
                    .unwrap();
                write!(karg.get_fb(), "  align({})\n", ph.p_align).unwrap();

                if ph.p_type == 1 {
                    if max_addr < ph.p_vaddr + ph.p_memsz {
                        max_addr = ph.p_vaddr + ph.p_memsz;
                    }
                    if base_addr > ph.p_vaddr {
                        base_addr = ph.p_vaddr;
                    }
                }
            }
            write!(karg.get_fb(), "addr_range: {:#018x}-{:#018x}\n", base_addr, max_addr);
            bootstrap_pages = (max_addr - base_addr + 4096) as usize / 4096;
            karg.set_kernaddr(base_addr as *mut core::ffi::c_void, bootstrap_pages);

            write!(
                karg.get_fb(),
                "Pages needed for kernel: {}\n",
                bootstrap_pages
            )
                .unwrap();

            let mut free_pages = 0;
            let mm_slice = unsafe { core::slice::from_raw_parts(mm_ptr, mm_count) };
            for mck in mm_slice
                .rchunks(1)
                    .filter(|x| x[0].ty == uefi::table::boot::MemoryType::CONVENTIONAL)
                    {
                        free_pages += mck[0].pages as usize;
                    }
            write!(karg.get_fb(), "Pages available: {}\n", free_pages).unwrap();

            let kernel_ptr = system_table
                .boot_services()
                .allocate_pages(
                    uefi::table::boot::AllocateType::AnyPages,
                    uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                    bootstrap_pages + 1,
                )
                .unwrap() as *mut u8;
            let mut kernel_slice = unsafe { core::slice::from_raw_parts_mut(kernel_ptr, bootstrap_pages * 4096) };

            // ELF dictates that all memory is zero'd initially
            kernel_slice.fill(0);

            write!(karg.get_fb(), "Base vaddr: {:#018x}\n", base_addr).unwrap();
            for ph in elfdata.program_headers.iter().filter(|x| x.p_type == 1) {
                write!(karg.get_fb(), "Writing kdata into: {:#018x}-{:#018x}\n",
                ((kernel_ptr as u64) + ph.p_vaddr - base_addr) as usize,
                ((kernel_ptr as u64) + ph.p_vaddr - base_addr + ph.p_filesz - 1) as usize,
                );
                for i in ph.p_offset..(ph.p_offset + ph.p_filesz) {
                    kernel_slice[((ph.p_vaddr - base_addr) + (i - ph.p_offset)) as usize] = kbytes[i as usize];
                };
            }

            write!(karg.get_fb(), "Loaded kernel pointer: {:#018x}\n", kernel_ptr as usize).unwrap();
            match support_huge_pages() {
                true => write!(karg.get_fb(), "CPU supports 1GiB pages\n").unwrap(),
                false => write!(karg.get_fb(), "CPU DOESN'T support 1GiB pages\n").unwrap(),
            };
            let mut cr0_content = 0;
            let mut cr3_content = 0;
            let mut cr4_content = 0;
            let mut ripval = 0;
            let mut rspval = 0;

            // This turns on PSE so we can use 1GiB pages
            unsafe { asm!(
                "mov {cval}, cr0",
                "mov {pgval}, cr3",
                "call 22f+rip",
                "22:",
                "pop {ripval}",
                "mov {rspval}, rsp",
                "mov {val}, cr4",
                "or {val},0x00000010",
                "mov cr4, {val}",
                "mov {val}, cr4",
                cval = out(reg) cr0_content,
                pgval = out(reg) cr3_content,
                ripval = out(reg) ripval,
                rspval = out(reg) rspval,
                val = out(reg) cr4_content,
            )};
            write!(karg.get_fb(), "CR0: {:#018x}\n", cr0_content).unwrap();
            write!(karg.get_fb(), "CR3: {:#018x}\n", cr3_content).unwrap();
            write!(karg.get_fb(), "CR4: {:#018x}\n", cr4_content).unwrap();
            write!(karg.get_fb(), "RIP: {:#018x}\n", ripval).unwrap();
            write!(karg.get_fb(), "RSP: {:#018x}\n", rspval).unwrap();

            // Allocate the new PML4 table
            let pml4_ptr = system_table
                .boot_services()
                .allocate_pages(
                    uefi::table::boot::AllocateType::AnyPages,
                    uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                    1,
                )
                .unwrap() as *mut paging::PDEntry;
            let mut pml4_slice = unsafe { core::slice::from_raw_parts_mut::<paging::PDEntry>(pml4_ptr, 512) };
            pml4_slice.fill(paging::PDEntry::new_null());

            // Allocate first PDPT table
            let pdpt_ptr = system_table
                .boot_services()
                .allocate_pages(
                    uefi::table::boot::AllocateType::AnyPages,
                    uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                    1,
                )
                .unwrap() as *mut paging::PDEntry;
            let mut pdpt_slice = unsafe { core::slice::from_raw_parts_mut::<paging::PDEntry>(pdpt_ptr, 512) };
            pdpt_slice.fill(paging::PDEntry::new_null());

            // Set the first entry in PML4 to this new physmem PDPT
            pml4_slice[0] = paging::PDEntry::from_paddr(pdpt_ptr as usize);

            // TODO: for now statically embed 64GB as the upper limit of physical mem
            //let phys_max = 0x10_0000_0000usize;
            let phys_max = 0x4_0000_0000usize;

            // Next, iterate for each 1GB of RAM, and create a corresponding entry in PDPT
            //for i in 0..(phys_max / 0x4000_0000usize) {
            for i in 0..512 {
                pdpt_slice[i] = paging::PDEntry::huge_from_paddr(i * 0x4000_0000);
            };

            // Allocate second PDPT table
            let pdpt_ptr = system_table
                .boot_services()
                .allocate_pages(
                    uefi::table::boot::AllocateType::AnyPages,
                    uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                    1,
                )
                .unwrap() as *mut paging::PDEntry;
            let mut pdpt_slice = unsafe { core::slice::from_raw_parts_mut::<paging::PDEntry>(pdpt_ptr, 512) };
            pdpt_slice.fill(paging::PDEntry::new_null());

            // Set the second entry in PML4 to this new physmem PDPT
            pml4_slice[1] = paging::PDEntry::from_paddr(pdpt_ptr as usize);

            // Identity-map second 512GB of memory
            for i in 0..512 {
                pdpt_slice[i] = paging::PDEntry::huge_from_paddr((1 << 39) + i * 0x4000_0000);
            };

            // Next, make sure the framebuffer is identity-mapped
            let fbptr = karg.get_fb().get_fb();
            write!(karg.get_fb(), "FB {:#?}, phys_max: {:#018x}\n", fbptr, phys_max).unwrap();
            /*if fbptr as usize >= phys_max {
                write!(karg.get_fb(), "FB identity mapped\n").unwrap();
                let fbaddr = fbptr as usize;
                let fb_pml4i = (fbaddr >> 39) & 0x1ff;
                let fb_pdpi = (fbaddr >> 30) & 0x1ff;
                write!(karg.get_fb(), "FB PML4i: {:#018x}\n", fb_pml4i).unwrap();
                if fb_pml4i > 0 {
                    // Need to make a new PML4 entry for framebuffer, and PDPT
                    // Allocate new PDPT table
                    let fb_pdpt_ptr = system_table
                        .boot_services()
                        .allocate_pages(
                            uefi::table::boot::AllocateType::AnyPages,
                            uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                            1,
                        )
                        .unwrap() as *mut paging::PDEntry;
                    write!(karg.get_fb(), "FB PDPT: {:#018x}\n", fb_pdpt_ptr as usize).unwrap();
                    let fb_pdpt_slice = unsafe { core::slice::from_raw_parts_mut::<paging::PDEntry>(fb_pdpt_ptr, 512) };
                    fb_pdpt_slice.fill(paging::PDEntry::new_null());

                    write!(karg.get_fb(), "FB PDPi: {:#018x}\n", fb_pdpi).unwrap();
                    fb_pdpt_slice[fb_pdpi] = paging::PDEntry::huge_from_paddr(fbaddr & !0xfff);
                    write!(karg.get_fb(), "FB PDP entry: {:?}\n", fb_pdpt_slice[fb_pdpi]).unwrap();

                    pml4_slice[fb_pml4i] = paging::PDEntry::from_paddr(fb_pdpt_ptr as usize);
                    write!(karg.get_fb(), "FB PML4 entry: {:?}\n", pml4_slice[fb_pml4i]).unwrap();
                } else {
                    write!(karg.get_fb(), "FB PDPTi: {:#018x}\n", fb_pdpi).unwrap();
                    pdpt_slice[fb_pdpi] = paging::PDEntry::huge_from_paddr(fbaddr & !0xfff);
                }
            }*/

            // Allocate kernel image PDPT table
            let kpdpt_ptr = system_table
                .boot_services()
                .allocate_pages(
                    uefi::table::boot::AllocateType::AnyPages,
                    uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                    1,
                )
                .unwrap() as *mut paging::PDEntry;
            let kpdpt_slice = unsafe { core::slice::from_raw_parts_mut::<paging::PDEntry>(kpdpt_ptr, 512) };
            kpdpt_slice.fill(paging::PDEntry::new_null());

            pml4_slice[(base_addr as usize >> 39) & 0x1ff] = paging::PDEntry::from_paddr(kpdpt_ptr as usize);

            for k in 0..=(bootstrap_pages >> 18) {
                // Allocate kernel image PDT table
                let kpdt_ptr = system_table
                    .boot_services()
                    .allocate_pages(
                        uefi::table::boot::AllocateType::AnyPages,
                        uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                        1,
                    )
                    .unwrap() as *mut paging::PDEntry;
                let kpdt_slice = unsafe { core::slice::from_raw_parts_mut::<paging::PDEntry>(kpdt_ptr, 512) };
                kpdt_slice.fill(paging::PDEntry::new_null());

                kpdpt_slice[k] = paging::PDEntry::from_paddr(kpdt_ptr as usize);

                // Allocate kernel image page table
                for j in 0..=(bootstrap_pages >> 9) {
                    let kpt_ptr = system_table
                        .boot_services()
                        .allocate_pages(
                            uefi::table::boot::AllocateType::AnyPages,
                            uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA,
                            1,
                        )
                        .unwrap() as *mut paging::PDEntry;

                    let kpt_slice = unsafe { core::slice::from_raw_parts_mut::<paging::PDEntry>(kpt_ptr, 512) };
                    kpt_slice.fill(paging::PDEntry::new_null());

                    kpdt_slice[j] = paging::PDEntry::from_paddr(kpt_ptr as usize);

                    for i in 0..512 {
                        kpt_slice[i] = paging::PDEntry::from_paddr(kernel_ptr as usize + (i * 0x1000) + (j << 21));
                    };
                }
            }

            write!(karg.get_fb(), "PML4({:#018x}) PDPT({:#018x})\n", pml4_ptr as usize, pdpt_ptr as usize).unwrap();
            wait_for_keypress(&mut system_table).unwrap();
            write!(karg.get_fb(), "Key pressed, continuing...\n").unwrap();

            let karg_copy_ptr = system_table
                .boot_services()
                .allocate_pool(uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA, core::mem::size_of::<KernelArgs>())
                .unwrap().as_ptr() as *mut KernelArgs;

            // Get the updated MemoryMap table
            unsafe { system_table.boot_services().free_pool(mm_ptr as *mut u8).unwrap() };
            (mm_ptr, mm_count) = get_mm(&system_table);
            karg.set_memmap(mm_ptr, mm_count);
            let _ = unsafe { system_table.exit_boot_services(uefi::table::boot::MemoryType::RUNTIME_SERVICES_DATA) };
            write!(karg.get_fb(), "Swapping page tables\n").unwrap();

            unsafe {
                asm!(
                    "cli",
                    "mov cr3, {val}",
                    val = in(reg) pml4_ptr,
                )
            };

            write!(karg.get_fb(), "Identity pages loaded for first {}GiB of ram\n", /*phys_max / 0x4000_0000*/1024).unwrap();

            if let Some(dyndata) = elfdata.dynamic {
                for dynentry in dyndata.dyns {
                    if dynentry.d_tag < 39 {
                        write!(karg.get_fb(), "DYN({})({:#018x}) ", dynentry.d_tag, dynentry.d_val).unwrap();
                    } else {
                        write!(karg.get_fb(), "DYN({:#x})({:#018x}) ", dynentry.d_tag, dynentry.d_val).unwrap();
                    }
                }
            }

            // TODO: This needs to be updated to jump to vaddr
            write!(karg.get_fb(), "\nJumping into kernel now at {:#018x}!", entaddr).unwrap();
            for i in 0..=10 {
                let bptr = (entaddr + i) as *const u8;
                write!(karg.get_fb(), "{:02x}-", unsafe { *bptr }).unwrap();
            };
            write!(karg.get_fb(), "\n").unwrap();
            //karg.get_fb().clear_console();
            unsafe { *karg_copy_ptr = karg };
            write!(karg.get_fb(), "Now jumping\n").unwrap();

            unsafe { asm!(
                "mov rax, {ka}",
                "push rax",
                "push rsp",
                "mov rax, {ep}",
                "pop rsi",
                "pop rdi",
                "jmp rax",
                ka = in(reg) karg_copy_ptr,
                ep = in(reg) entaddr,
                options(noreturn),
            )};
        };
    };

    // Tell the UEFI firmware we exited without error
    wait_for_keypress(&mut system_table).unwrap();
    Status::SUCCESS
}
