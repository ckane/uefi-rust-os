/*
 * 64               48        39        30        21        12           0
 *  |                |         |         |         |         |           |
 *  +----------------+---------+---------+---------+---------+-----------+
 *  |                |         |         |         |         |           |
 *  +----------------+---------+---------+---------+---------+-----------+
 *      Reserved        PML4      PDPT       PDE       PT        Page
 *     (= bit 47)       Index     Index     Index    Index      Offset
 *
 *     Each table contains 2^9 entries (512 entries) of 8 bytes each, so
 *     8*512 = 4096 bytes = 1 page per table
 */

const NULL_PDE: usize = 0x0000000000000000;

/* For a supervisor page, set the P and W bits */
const SUP_PAGE: usize = 0x0000000000000003;
const SUP_HUGE_PAGE: usize = 0x0000000000000083;

#[derive(Copy, Clone, Debug)]
pub struct PDEntry(usize);

impl PDEntry {
    pub fn new_null() -> Self {
        Self(NULL_PDE)
    }
    pub fn from_paddr(paddr: usize) -> Self {
        Self(paddr | SUP_PAGE)
    }
    pub fn huge_from_paddr(paddr: usize) -> Self {
        Self(paddr | SUP_HUGE_PAGE)
    }
    pub fn is_present(&self) -> bool {
        (self.0 & 1) != 0
    }
    pub fn is_writable(&self) -> bool {
        (self.0 & 2) != 0
    }
    pub fn is_user(&self) -> bool {
        (self.0 & 4) != 0
    }
    pub fn is_write_thru(&self) -> bool {
        (self.0 & 8) != 0
    }
    pub fn is_cache_disabled(&self) -> bool {
        (self.0 & 0x10) != 0
    }
    pub fn is_accessed(&self) -> bool {
        (self.0 & 0x20) != 0
    }
    pub fn is_ps(&self) -> bool {
        (self.0 & 0x80) != 0
    }
    pub fn paddr(&self) -> usize {
        self.0 & 0x0fffffffff000
    }
    pub fn set_present(&mut self, p: bool) {
        if p {
            self.0 |= 1
        } else {
            self.0 &= !1
        };
    }
    pub fn set_writable(&mut self, w: bool) {
        if w {
            self.0 |= 2
        } else {
            self.0 &= !2
        };
    }
    pub fn set_user(&mut self, u: bool) {
        if u {
            self.0 |= 4
        } else {
            self.0 &= !4
        };
    }
    pub fn set_write_thru(&mut self, wt: bool) {
        if wt {
            self.0 |= 8
        } else {
            self.0 &= !8
        };
    }
    pub fn set_cache_disabled(&mut self, cd: bool) {
        if cd {
            self.0 |= 0x10
        } else {
            self.0 &= !0x10
        };
    }
    pub fn set_accessed(&mut self, a: bool) {
        if a {
            self.0 |= 0x20
        } else {
            self.0 &= !0x20
        };
    }
    pub fn set_ps(&mut self, ps: bool) {
        if ps {
            self.0 |= 0x80
        } else {
            self.0 &= !0x80
        };
    }
}
