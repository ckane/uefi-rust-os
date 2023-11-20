use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Point, Size};
use embedded_graphics::mono_font::{ascii::FONT_6X10, MonoTextStyle};
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::Pixel;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::table::boot::ScopedProtocol;

/// A Console type which keeps track of dimensional and address data for the
/// FrameBuffer provided by UEFI
pub struct Console {
    /// The address pointer of the framebuffer
    fbptr: *mut u8,

    /// The width (in pixels) of a framebuffer row
    fbwidth: usize,

    /// The number of framebuffer rows on the screen
    fbheight: usize,
    
    /// The "stride" width of a framebuffer row (stride >= fbwidth)
    fbstride: usize,

    /// The Pixel Format
    pixel_format: PixelFormat,
}

impl Console {
    /// Takes a `GraphicsOutput` scoped protocol and instantiates a new Console
    /// object based upon the current mode info and framebuffer address
    pub fn new_from_uefi_gfx(mut gfx: ScopedProtocol<GraphicsOutput>) -> Self {
        let mode_info = gfx.current_mode_info();
        let (w, h) = mode_info.resolution();
        Console {
            fbptr: gfx.frame_buffer().as_mut_ptr(),
            fbwidth: w,
            fbheight: h,
            fbstride: mode_info.stride(),
            pixel_format: mode_info.pixel_format(),
        } 
    }

    /// Writes the string constant in s to the location (x, y). Note the y location refers to the
    /// lower-left corner of the character box, rather than the upper-left corner.
    pub fn write_str<'a>(&mut self, s: &'a str, x: i32, y: i32) -> Result<(), ConsoleError> {
        // Allocate a style to display Yellow text using a 6x10 built-in font
        let sty = MonoTextStyle::new(&FONT_6X10, Rgb888::YELLOW);

        // Create the text graphic, and write it to the Console (self)
        Text::new(s, Point::new(x, y), sty).draw(self)?;
        Ok(())
    }
}

impl OriginDimensions for Console {
    fn size(&self) -> Size {
        Size::new(self.fbwidth as u32, self.fbheight as u32)
    }
}

pub enum ConsoleError {
    BoundsError,
}

impl DrawTarget for Console {
    /// Code is simplified (for now) by statically setting the Color to Rgb888
    type Color = Rgb888;
    type Error = ConsoleError;
    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(Point { x: px, y: py }, color) in pixels.into_iter() {
            // Convert point positions to usize
            let x = px as usize;
            let y = py as usize;
            if (x < self.fbwidth) && (y < self.fbheight) {
                /* Calculate offset into framebuffer */
                let offset = (y * (self.fbstride * 4)) + (x * 4);
                let fbsize = self.fbstride * self.fbheight * 4;
                let fb = unsafe { core::slice::from_raw_parts_mut(self.fbptr, fbsize) };
                fb[offset + 1] = color.g();

                // Support swapped-ordering when we are a BGR versus RGB Console. This handles
                // the conversion required because we set the DrawTarget's Color type to Rgb888
                // for code simplicity.
                if self.pixel_format == PixelFormat::Bgr {
                    fb[offset] = color.b();
                    fb[offset + 2] = color.r();
                } else {
                    fb[offset] = color.r();
                    fb[offset + 2] = color.b();
                }
            } else {
                // If given an invalid bound, then return an error
                return Err(ConsoleError::BoundsError)
            }
        }
        Ok(())
    }
}
