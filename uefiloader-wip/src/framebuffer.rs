use core::fmt::Write;
use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Point, Size},
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb888,
    prelude::*,
    primitives::rectangle::Rectangle,
    text::Text,
    Pixel,
};

#[derive(Clone, Copy, Debug)]
pub struct UnsafeFrameBuffer {
    fbptr: *mut u8,
    fx: usize,
    fy: usize,
    stride: usize,
    fbsize: usize,
    rmask: u32,
    gmask: u32,
    bmask: u32,
    txtcur_x: usize,
    txtcur_y: usize,
    format: uefi::proto::console::gop::PixelFormat,
}

impl Default for UnsafeFrameBuffer {
    fn default() -> Self {
        UnsafeFrameBuffer {
            fbptr: core::ptr::null_mut(),
            fx: 0,
            fy: 0,
            format: uefi::proto::console::gop::PixelFormat::Rgb,
            rmask: 0,
            bmask: 0,
            gmask: 0,
            fbsize: 0,
            stride: 0,
            txtcur_x: 0,
            txtcur_y: 0,
        }
    }
}

impl OriginDimensions for UnsafeFrameBuffer {
    fn size(&self) -> embedded_graphics::geometry::Size {
        embedded_graphics::geometry::Size::new(self.fx as u32, self.fy as u32)
    }
}

impl DrawTarget for UnsafeFrameBuffer {
    type Error = core::convert::Infallible;
    type Color = embedded_graphics::pixelcolor::Rgb888;

    fn draw_iter<I>(&mut self, pixels: I) -> core::result::Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(Point { x: px, y: py }, color) in pixels.into_iter() {
            let x = px as usize;
            let y = py as usize;
            if (x < self.fx) && (y < self.fy) {
                /* Calculate offset into framebuffer */
                let offset = (y * (self.stride * 4)) + (x * 4);
                let fb = unsafe { core::slice::from_raw_parts_mut(self.fbptr, self.fbsize) };
                fb[offset] = color.b();
                fb[offset + 1] = color.g();
                fb[offset + 2] = color.r();
            }
        }
        Ok(())
    }
}

impl Write for UnsafeFrameBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        /* TODO - smarter about breaking too-long strings. */
        for i in 0..s.len() {
            let text_style = MonoTextStyle::new(&FONT_6X10, Rgb888::YELLOW);
            if (self.txtcur_y * 10) + 20 < self.fy {
                if &s[i..(i + 1)] == "\n" {
                    self.txtcur_y += 1;
                    self.txtcur_x = 0;
                } else {
                    if (self.txtcur_x * 7) + 7 >= self.fx {
                        self.txtcur_y += 1;
                        self.txtcur_x = 0;
                    }
                    Text::new(
                        &s[i..(i + 1)],
                        Point::new((self.txtcur_x * 7) as i32, (self.txtcur_y * 10 + 9) as i32),
                        text_style,
                    )
                    .draw(self)
                    .unwrap();

                    // Advance the cursor
                    self.txtcur_x += 1;
                }
            } else {
                // TODO: Scroll the buffer up one row
                self.scroll_one();
                self.txtcur_y -= 1;
                self.txtcur_x = 0;
                return self.write_str(s);
            }
        }
        Ok(())
    }
}

impl UnsafeFrameBuffer {
    pub fn clear_console(&mut self) {
        let _ = self.clear(Rgb888::new(0, 0, 0));
        self.txtcur_x = 0;
        self.txtcur_y = 0;
    }

    pub fn get_fb(&mut self) -> *mut u8 {
        self.fbptr
    }

    pub fn size(&self) -> usize {
        self.fbsize
    }

    pub fn new(
        fbptr: *mut u8,
        fbsize: usize,
        fx: usize,
        fy: usize,
        stride: usize,
        format: uefi::proto::console::gop::PixelFormat,
        rmask: u32,
        gmask: u32,
        bmask: u32,
    ) -> UnsafeFrameBuffer {
        UnsafeFrameBuffer {
            fbptr,
            fx,
            fy,
            format,
            rmask,
            bmask,
            gmask,
            fbsize,
            stride,
            txtcur_x: 0,
            txtcur_y: 0,
        }
    }

    fn scroll_one(&mut self) {
        let src_range = Rectangle {
            top_left: Point { x: 0, y: 10 },
            size: Size {
                width: self.fx as u32,
                height: self.fy as u32 - 10,
            },
        };
        self.s2s_blit(src_range, Point { x: 0, y: 0 });
        let fb = unsafe { core::slice::from_raw_parts_mut(self.fbptr, self.fbsize) };
        let blk_offset = (self.fy - 20) * self.stride * 4;
        fb.get_mut(blk_offset..(self.fy * self.stride * 4))
            .unwrap()
            .fill(0);
    }

    pub fn s2s_blit(&mut self, src_rect: Rectangle, dst_top_left: Point) {
        let tly = src_rect.top_left.y as usize;
        let maxw = src_rect.size.width as usize;
        let maxh = src_rect.size.height as usize;
        let tlx = src_rect.top_left.x as usize;
        let fb = unsafe { core::slice::from_raw_parts_mut(self.fbptr, self.fbsize) };
        for yoffs in 0..(src_rect.size.height as usize) {
            let ypos = if src_rect.top_left.y < dst_top_left.y {
                maxh - yoffs - 1
            } else {
                yoffs
            };
            let old_offset = ((tly + ypos) * (self.stride * 4)) + (tlx * 4);
            let new_offset = ((dst_top_left.y as usize + ypos) * (self.stride * 4))
                + (dst_top_left.x as usize * 4);
            fb.copy_within(old_offset..(old_offset + (maxw * 4)), new_offset);
        }
    }
}
