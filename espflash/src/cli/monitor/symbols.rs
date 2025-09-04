use std::{borrow::Cow, error::Error};

use addr2line::{
    Context,
    LookupResult,
    gimli::{self, EndianSlice, LittleEndian},
};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, read::File};

// Wrapper around addr2line that allows to look up function names and
// locations from a given address.
pub(crate) struct Symbols {
    _data: Box<[u8]>,
    object: File<'static, &'static [u8]>,
    dwarf: gimli::DwarfSections<Cow<'static, [u8]>>,
}

// https://github.com/gimli-rs/addr2line/blob/master/benches/bench.rs#L27-L45
fn dwarf_load<'a>(object: &File<'a>) -> gimli::DwarfSections<Cow<'a, [u8]>> {
    let load_section = |id: gimli::SectionId| -> Result<Cow<'a, [u8]>, gimli::Error> {
        Ok(object
            .section_by_name(id.name())
            .map(|section| section.uncompressed_data().unwrap())
            .unwrap_or(Cow::Borrowed(&[][..])))
    };
    gimli::DwarfSections::load(&load_section).unwrap()
}

fn dwarf_borrow<'a>(
    dwarf: &'a gimli::DwarfSections<Cow<'_, [u8]>>,
) -> gimli::Dwarf<gimli::EndianSlice<'a, gimli::LittleEndian>> {
    let borrow_section: &dyn for<'b> Fn(
        &'b Cow<'_, [u8]>,
    ) -> gimli::EndianSlice<'b, gimli::LittleEndian> =
        &|section| gimli::EndianSlice::new(section, gimli::LittleEndian);
    dwarf.borrow(&borrow_section)
}

impl Symbols {
    /// Tries to create a new `Symbols` instance from the given ELF file bytes.
    pub fn try_from(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let data = bytes.to_vec().into_boxed_slice();
        let bytes_ref: &'static [u8] = unsafe { std::mem::transmute(data.as_ref()) };
        let object = File::parse(bytes_ref)?;
        let dwarf = dwarf_load(&object);

        Ok(Self {
            _data: data,
            object,
            dwarf,
        })
    }

    /// Gets the context, creating it on-demand.
    fn get_context(&self) -> Result<Context<EndianSlice<'_, LittleEndian>>, gimli::Error> {
        let borrowed_dwarf = dwarf_borrow(&self.dwarf);
        let result = Context::from_dwarf(borrowed_dwarf);

        if let Err(ref e) = result {
            eprintln!("Failed to create DWARF context: {e}");
        }

        result
    }

    /// Returns the name of the function at the given address, if one can be
    /// found.
    pub fn name(&self, addr: u64) -> Option<String> {
        // No need to try an address not contained in any segment:
        if !self.object.segments().any(|segment| {
            (segment.address()..(segment.address() + segment.size())).contains(&addr)
        }) {
            return None;
        }

        // The basic steps here are:
        //   1. Find which frame `addr` is in
        //   2. Look up and demangle the function name
        //   3. If no function name is found, try to look it up in the object file
        //      directly
        //   4. Return a demangled function name, if one was found
        let ctx = self.get_context().ok()?;
        let mut frames = match ctx.find_frames(addr) {
            LookupResult::Output(result) => result.unwrap(),
            LookupResult::Load { .. } => unimplemented!(),
        };

        frames
            .next()
            .ok()
            .flatten()
            .and_then(|frame| {
                frame
                    .function
                    .and_then(|name| name.demangle().map(|s| s.into_owned()).ok())
            })
            .or_else(|| {
                // Don't use `symbol_map().get(addr)` - it's documentation says "Get the symbol
                // before the given address." which might be totally wrong
                let symbol = self.object.symbols().find(|symbol| {
                    (symbol.address()..=(symbol.address() + symbol.size())).contains(&addr)
                });

                if let Some(symbol) = symbol {
                    match symbol.name() {
                        Ok(name) if !name.is_empty() => Some(
                            addr2line::demangle_auto(std::borrow::Cow::Borrowed(name), None)
                                .to_string(),
                        ),
                        _ => None,
                    }
                } else {
                    None
                }
            })
    }

    /// Returns the file name and line number of the function at the given
    /// address, if one can be.
    pub fn location(&self, addr: u64) -> Option<(String, u32)> {
        // Find the location which `addr` is in. If we can dedetermine a file name and
        // line number for this function we will return them both in a tuple.
        let ctx = self.get_context().ok()?;
        ctx.find_location(addr).ok()?.map(|location| {
            let file = location.file.map(|f| f.to_string());
            let line = location.line;

            match (file, line) {
                (Some(file), Some(line)) => Some((file, line)),
                _ => None,
            }
        })?
    }
}
