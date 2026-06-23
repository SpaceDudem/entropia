
use std::collections::HashMap;
use std::io::Write;

// COFF constants. Spelled out locally so the emitter stays
// self-contained (the compiler crate doesn't need windows-sys).

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

// Section characteristics.
pub const IMAGE_SCN_CNT_CODE:               u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA:   u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_ALIGN_1BYTES:           u32 = 0x0010_0000;
pub const IMAGE_SCN_ALIGN_4BYTES:           u32 = 0x0030_0000;
pub const IMAGE_SCN_ALIGN_8BYTES:           u32 = 0x0040_0000;
pub const IMAGE_SCN_ALIGN_16BYTES:          u32 = 0x0050_0000;
pub const IMAGE_SCN_MEM_EXECUTE:            u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ:               u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE:              u32 = 0x8000_0000;

pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const IMAGE_SYM_CLASS_STATIC:   u8 = 3;

// 0x20 marks a function symbol (used for go). Aux records for
// function size aren't emitted in V1.
pub const IMAGE_SYM_TYPE_NULL:       u16 = 0x00;
pub const IMAGE_SYM_DTYPE_FUNCTION:  u16 = 0x20;

// Relocation types for AMD64.
pub const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
pub const IMAGE_REL_AMD64_ADDR64:   u16 = 0x0001;
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const IMAGE_REL_AMD64_REL32:    u16 = 0x0004;

// Public artifact: codegen builds a CoffObject and hands it to emit.
// Symbols are deduplicated; relocations index into symbols.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymKind {
    /// .text static. External only when the symbol is go.
    TextStatic,
    TextExtern,
    DataStatic { section: SectionId },
    /// Loader-resolved: __imp_BeaconPrintf, __imp_USER32$MessageBoxA, ...
    Undefined,
}

/// Section number is 1-based in COFF (0 = undefined). Order here
/// matches the order sections get emitted into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionId { Text, Rdata, Data, Bss }

#[derive(Debug, Clone)]
pub struct CoffSymbol {
    pub name:    String,
    pub kind:    SymKind,
    /// Offset within the symbol's section. Ignored for Undefined.
    pub value:   u32,
}

#[derive(Debug, Clone)]
pub struct CoffReloc {
    pub at:      u32,
    pub sym:     usize,
    pub ty:      u16,
}

#[derive(Debug, Clone, Default)]
pub struct CoffSection {
    pub bytes:   Vec<u8>,
    pub relocs:  Vec<CoffReloc>,
}

#[derive(Debug, Default)]
pub struct CoffObject {
    pub text:    CoffSection,
    pub rdata:   CoffSection,
    pub data:    CoffSection,
    pub bss_size: u32,   // .bss carries no raw bytes; just a size
    pub symbols: Vec<CoffSymbol>,
}

impl CoffObject {
    pub fn new() -> Self { Self::default() }

    /// Find-or-add a symbol; returns its index. Idempotent on name.
    pub fn intern(&mut self, name: &str, kind: SymKind, value: u32) -> usize {
        if let Some(i) = self.symbols.iter().position(|s| s.name == name) {
            return i;
        }
        self.symbols.push(CoffSymbol {
            name: name.to_string(),
            kind, value,
        });
        self.symbols.len() - 1
    }
}

// Emitter. File layout: [file header | section headers | raw section
// bytes | per-section relocs | symbol table | string table].
pub fn emit(obj: &CoffObject) -> Result<Vec<u8>, String> {
    // .text is always present; other sections appear iff they have
    // content. SectionId order is stable so prior symbol indices resolve.
    let mut sections: Vec<(&'static str, u32, &CoffSection, SectionId, u32)> = Vec::new();

    // .bss placeholder. Don't reuse another section here - the
    // header writer reads body.relocs.len from it and a wrong
    // placeholder makes the loader apply every reloc twice.
    static EMPTY_SECTION: CoffSection = CoffSection {
        bytes:  Vec::new(),
        relocs: Vec::new(),
    };

    sections.push((
        ".text",
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_16BYTES,
        &obj.text,
        SectionId::Text,
        0,
    ));
    if !obj.rdata.bytes.is_empty() {
        sections.push((
            ".rdata",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_8BYTES,
            &obj.rdata,
            SectionId::Rdata,
            0,
        ));
    }
    if !obj.data.bytes.is_empty() {
        sections.push((
            ".data",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_8BYTES,
            &obj.data,
            SectionId::Data,
            0,
        ));
    }
    if obj.bss_size > 0 {
        sections.push((
            ".bss",
            IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_8BYTES,
            &EMPTY_SECTION,
            SectionId::Bss,
            obj.bss_size,
        ));
    }

    // SectionId -> 1-based section number for the symbol table.
    let mut sec_num: HashMap<SectionId, i16> = HashMap::new();
    for (i, (_, _, _, id, _)) in sections.iter().enumerate() {
        sec_num.insert(*id, (i as i16) + 1);
    }

    // Compute offsets so section headers can point at them.
    let header_size       = 20;
    let section_hdr_size  = 40 * sections.len();
    let mut cursor = header_size + section_hdr_size;

    // Section raw data offsets.
    let mut raw_offsets: Vec<u32> = Vec::with_capacity(sections.len());
    for (_, _, body, _, bss_size) in &sections {
        if *bss_size > 0 {
            raw_offsets.push(0);     // .bss has no raw data; pointer is 0
        } else if body.bytes.is_empty() {
            raw_offsets.push(0);
        } else {
            raw_offsets.push(cursor as u32);
            cursor += body.bytes.len();
        }
    }

    // Relocation table offsets.
    let mut reloc_offsets: Vec<u32> = Vec::with_capacity(sections.len());
    for (_, _, body, _, _) in &sections {
        if body.relocs.is_empty() {
            reloc_offsets.push(0);
        } else {
            reloc_offsets.push(cursor as u32);
            cursor += body.relocs.len() * 10;
        }
    }

    let symtab_offset = cursor as u32;
    cursor += obj.symbols.len() * 18;        // 18 bytes per symbol, no aux records
    let strtab_offset = cursor;

    // String table: <=8 byte names inline in the symbol's Name[8] slot.
    // Longer names: Name[0..4] = 0, Name[4..8] = LE offset into strtab.
    let mut strtab: Vec<u8> = Vec::new();
    strtab.extend_from_slice(&[0, 0, 0, 0]);  // placeholder for size (filled at end)

    let intern_name = |strtab: &mut Vec<u8>, name: &str| -> [u8; 8] {
        let mut out = [0u8; 8];
        if name.len() <= 8 {
            for (i, b) in name.bytes().enumerate() { out[i] = b; }
            return out;
        }
        let off = strtab.len() as u32;
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
        out[4..8].copy_from_slice(&off.to_le_bytes());
        out
    };

    let mut out: Vec<u8> = Vec::new();

    // 1. File header.
    out.write_all(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes()).unwrap();
    out.write_all(&(sections.len() as u16).to_le_bytes()).unwrap();
    out.write_all(&0u32.to_le_bytes()).unwrap();          // TimeDateStamp - leave zero for reproducible builds
    out.write_all(&symtab_offset.to_le_bytes()).unwrap();
    out.write_all(&(obj.symbols.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&0u16.to_le_bytes()).unwrap();          // SizeOfOptionalHeader - 0 for object files
    out.write_all(&0u16.to_le_bytes()).unwrap();          // Characteristics - 0 is fine for relocatable object

    // 2. Section headers.
    for (i, (name, chars, body, _id, bss_size)) in sections.iter().enumerate() {
        let mut name_bytes = [0u8; 8];
        for (j, b) in name.bytes().enumerate() { if j < 8 { name_bytes[j] = b; } }
        out.write_all(&name_bytes).unwrap();
        // VirtualSize/Address: 0/0 for object files. SizeOfRawData
        // doubles as .bss size when there's no raw data.
        out.write_all(&0u32.to_le_bytes()).unwrap();
        out.write_all(&0u32.to_le_bytes()).unwrap();
        let raw_size = if *bss_size > 0 { *bss_size } else { body.bytes.len() as u32 };
        out.write_all(&raw_size.to_le_bytes()).unwrap();
        out.write_all(&raw_offsets[i].to_le_bytes()).unwrap();
        out.write_all(&reloc_offsets[i].to_le_bytes()).unwrap();
        out.write_all(&0u32.to_le_bytes()).unwrap();      // PointerToLineNumbers (deprecated)
        out.write_all(&(body.relocs.len() as u16).to_le_bytes()).unwrap();
        out.write_all(&0u16.to_le_bytes()).unwrap();      // NumberOfLineNumbers
        out.write_all(&chars.to_le_bytes()).unwrap();
    }

    // 3. Section raw data, in declaration order.
    for (_, _, body, _, bss_size) in &sections {
        if *bss_size == 0 {
            out.write_all(&body.bytes).unwrap();
        }
    }

    // 4. Relocation tables per section. SymbolTableIndex is 0-based
    //    into obj.symbols.
    for (_, _, body, _, _) in &sections {
        for r in &body.relocs {
            out.write_all(&r.at.to_le_bytes()).unwrap();
            out.write_all(&(r.sym as u32).to_le_bytes()).unwrap();
            out.write_all(&r.ty.to_le_bytes()).unwrap();
        }
    }

    // 5. Symbol table.
    for s in &obj.symbols {
        let name_bytes = intern_name(&mut strtab, &s.name);
        out.write_all(&name_bytes).unwrap();
        out.write_all(&s.value.to_le_bytes()).unwrap();

        let (section_number, storage_class, ty): (i16, u8, u16) = match s.kind {
            SymKind::TextStatic => (
                *sec_num.get(&SectionId::Text).unwrap(),
                IMAGE_SYM_CLASS_STATIC,
                IMAGE_SYM_DTYPE_FUNCTION,
            ),
            SymKind::TextExtern => (
                *sec_num.get(&SectionId::Text).unwrap(),
                IMAGE_SYM_CLASS_EXTERNAL,
                IMAGE_SYM_DTYPE_FUNCTION,
            ),
            SymKind::DataStatic { section } => (
                *sec_num.get(&section).unwrap(),
                IMAGE_SYM_CLASS_STATIC,
                IMAGE_SYM_TYPE_NULL,
            ),
            SymKind::Undefined => (
                0,
                IMAGE_SYM_CLASS_EXTERNAL,
                IMAGE_SYM_TYPE_NULL,
            ),
        };
        out.write_all(&section_number.to_le_bytes()).unwrap();
        out.write_all(&ty.to_le_bytes()).unwrap();
        out.write_all(&[storage_class]).unwrap();
        out.write_all(&[0u8]).unwrap();                   // NumberOfAuxSymbols
    }

    // 6. String table: backpatch the size and append.
    let strtab_size = strtab.len() as u32;
    strtab[0..4].copy_from_slice(&strtab_size.to_le_bytes());
    out.write_all(&strtab).unwrap();

    let _ = strtab_offset;
    Ok(out)
}
