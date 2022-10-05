use std::iter::once;

use super::ImageFormat;
use crate::{
    elf::{CodeSegment, FirmwareImage, RomSegment},
    error::Error,
};

const DIRECT_BOOT_MAGIC: &[u8] = &[0x1d, 0x04, 0xdb, 0xae, 0x1d, 0x04, 0xdb, 0xae];

/// Image format for ESP32 family chips not using a second-stage bootloader
pub struct DirectBootFormat<'a> {
    segment: RomSegment<'a>,
}

impl<'a> DirectBootFormat<'a> {
    pub fn new(image: &'a dyn FirmwareImage<'a>, magic_offset: usize) -> Result<Self, Error> {
        let mut segment = image
            .segments_with_load_addresses()
            .map(|mut segment| {
                // Map the address to the first 4MB of address space
                segment.addr %= 0x40_0000;
                segment
            })
            .fold(CodeSegment::default(), |mut a, b| {
                a += &b;
                a
            });

        segment.pad_align(4);

        if segment.addr != 0
            || (segment.data().len() >= magic_offset + 8
                && &segment.data()[magic_offset..][..8] != DIRECT_BOOT_MAGIC)
        {
            return Err(Error::InvalidDirectBootBinary);
        }

        Ok(Self {
            segment: segment.into(),
        })
    }
}

impl<'a> ImageFormat<'a> for DirectBootFormat<'a> {
    fn flash_segments<'b>(&'b self) -> Box<dyn Iterator<Item = RomSegment<'b>> + 'b>
    where
        'a: 'b,
    {
        Box::new(once(self.segment.borrow()))
    }

    fn ota_segments<'b>(&'b self) -> Box<dyn Iterator<Item = RomSegment<'b>> + 'b>
    where
        'a: 'b,
    {
        Box::new(once(self.segment.borrow()))
    }
}