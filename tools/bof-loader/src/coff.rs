// SPDX-License-Identifier: Apache-2.0
//! COFF object-file parser.
//!
//! Read-only parsing of a `.obj` produced by `entc compile
//! --type=bof|coff` (or any standard COFF AMD64 object). Reads only
//! what the loader needs: file header, section headers, symbol
//! table, string table, relocations.
//!
//! Stays alloc-light - the input bytes stay live for the whole load,
//! so the parser hands out slices into them rather than copying.

// Microsoft COFF constants we care about, spelled out rather than
// pulled from windows-sys so the parser stays compatible with the
// emitter (`src/coff.rs` in the compiler crate uses the same values).

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_REL_AMD64_ADDR64:   u16 = 0x0001;
pub const IMAGE_REL_AMD64_REL32:    u16 = 0x0004;

pub struct ParsedCoff<'a> {
    pub bytes:      &'a [u8],
    pub n_sections: u16,
    pub symtab_off: usize,
    pub n_symbols:  u32,
    /// Cached string table starting at `symtab + 18 * n_symbols`.
    /// First 4 bytes are the size (including the 4-byte size field).
    pub strtab_off: usize,
}

impl<'a> ParsedCoff<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < 20 {
            return Err("file too small to be a COFF object".into());
        }
        let machine = u16::from_le_bytes([bytes[0], bytes[1]]);
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(format!(
                "expected AMD64 machine (0x{:04x}), got 0x{machine:04x}",
                IMAGE_FILE_MACHINE_AMD64
            ));
        }
        let n_sections = u16::from_le_bytes([bytes[2], bytes[3]]);
        let symtab_off = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let n_symbols  = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let strtab_off = symtab_off + 18 * n_symbols as usize;
        Ok(Self { bytes, n_sections, symtab_off, n_symbols, strtab_off })
    }

    pub fn section(&self, i: u16) -> SectionInfo<'a> {
        let base = 20 + 40 * i as usize;
        let raw_size  = u32::from_le_bytes(self.bytes[base+16..base+20].try_into().unwrap());
        let raw_off   = u32::from_le_bytes(self.bytes[base+20..base+24].try_into().unwrap());
        let reloc_off = u32::from_le_bytes(self.bytes[base+24..base+28].try_into().unwrap());
        let n_relocs  = u16::from_le_bytes(self.bytes[base+32..base+34].try_into().unwrap());
        let chars     = u32::from_le_bytes(self.bytes[base+36..base+40].try_into().unwrap());
        let name = {
            let raw = &self.bytes[base..base+8];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            std::str::from_utf8(&raw[..end]).unwrap_or("?").to_string()
        };
        SectionInfo {
            name,
            raw_size,
            raw: if raw_off == 0 { &[] } else {
                &self.bytes[raw_off as usize .. raw_off as usize + raw_size as usize]
            },
            relocs: if reloc_off == 0 { &[] } else {
                &self.bytes[reloc_off as usize .. reloc_off as usize + 10 * n_relocs as usize]
            },
            characteristics: chars,
        }
    }

    pub fn symbol_name(&self, idx: u32) -> String {
        let base = self.symtab_off + 18 * idx as usize;
        let raw = &self.bytes[base..base+8];
        if raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
            let off = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
            let start = self.strtab_off + off;
            let end = self.bytes[start..].iter().position(|&b| b == 0)
                .map(|n| start + n).unwrap_or(self.bytes.len());
            std::str::from_utf8(&self.bytes[start..end]).unwrap_or("?").to_string()
        } else {
            let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
            std::str::from_utf8(&raw[..end]).unwrap_or("?").to_string()
        }
    }

    pub fn symbol_value(&self, idx: u32) -> u32 {
        let base = self.symtab_off + 18 * idx as usize;
        u32::from_le_bytes(self.bytes[base+8..base+12].try_into().unwrap())
    }

    /// 1-based section number, or 0 for undefined (external) symbols.
    /// Stored as a signed 16-bit in the COFF spec - `IMAGE_SYM_UNDEFINED = 0`,
    /// `IMAGE_SYM_ABSOLUTE = -1`, `IMAGE_SYM_DEBUG = -2`; we only care about
    /// the >= 1 cases plus 0.
    pub fn symbol_section(&self, idx: u32) -> i16 {
        let base = self.symtab_off + 18 * idx as usize;
        i16::from_le_bytes(self.bytes[base+12..base+14].try_into().unwrap())
    }
}

pub struct SectionInfo<'a> {
    pub name:            String,
    pub raw_size:        u32,
    pub raw:             &'a [u8],
    pub relocs:          &'a [u8],
    pub characteristics: u32,
}
