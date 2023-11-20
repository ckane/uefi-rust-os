use acpi::{AcpiHandler, PhysicalMapping};

#[derive(Clone)]
pub struct IdentityAcpiHandler;

impl AcpiHandler for IdentityAcpiHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        // Since we are working with identity-mapped physical pages, and already
        // Ring 0, we can simply return the data requested back to the caller
        PhysicalMapping::new(
            physical_address,
            core::ptr::NonNull::<T>::new_unchecked(physical_address as *mut T),
            size,
            size,
            Self,
        )
    }

    /// This can simply be a no-op because the region is always availabe in UEFI
    fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) { }
}
