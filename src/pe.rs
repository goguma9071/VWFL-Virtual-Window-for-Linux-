// src/pe.rs

use object::{File, Object, ObjectSection, Architecture, LittleEndian};
use std::fmt;
use std::collections::HashMap;

/// PE 파일의 한 섹션에 대한 정보를 담는 구조체
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: String,
    pub rva: u32,
    pub ordinal: u16,
    pub forwarder: Option<String>, // 포워더 문자열 (예: "NTOSKRNL.KiService")
}

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<ImportFunction>,
}

#[derive(Debug, Clone)]
pub struct ImportFunction {
    pub name: String, // 함수 이름 (Ordinal Import인 경우 "#123" 형식)
    pub iat_rva: u32, // 실제 주소를 적어야 할 IAT의 RVA
}

/// 파싱된 PE 파일 전체를 나타내는 구조체
#[derive(Debug)]
pub struct PeFile {
    pub entry_point: u64,
    pub architecture: Architecture,
    pub image_base: u64,
    pub sections: Vec<Section>,
    pub header_data: Vec<u8>, 
    pub pdb_name: String,
    pub pdb_guid_age: String,
    
    // Raw Data Access를 위한 원본 바이트 (참조용)
    raw_bytes: Vec<u8>,
}

pub fn parse(bytes: &[u8]) -> Result<PeFile, &'static str> {
    let mut pe = PeFile::from_bytes(bytes)?;
    
    let header_size = if !pe.sections.is_empty() {
        4096.min(bytes.len())
    } else {
        bytes.len().min(4096)
    };
    pe.header_data = bytes[..header_size].to_vec();
    
    Ok(pe)
}

impl PeFile {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let file = File::parse(bytes).map_err(|_| "Failed to parse PE file")?;

        let (pdb_name, pdb_guid_age) = match file.pdb_info() {
            Ok(Some(info)) => {
                let name = String::from_utf8_lossy(info.path()).to_string();
                let guid = info.guid();
                let guid_str = format!(
                    "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                    guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7], guid[8], guid[9], guid[10],
                    info.age()
                );
                (name, guid_str)
            }
            _ => ("Unknown".to_string(), "Unknown".to_string()),
        };

        let (entry_point, architecture, image_base, sections) = match file {
            File::Pe32(pe) => {
                let sections = Self::extract_sections(&pe)?;
                let image_base = pe.nt_headers().optional_header.image_base.get(LittleEndian) as u64;
                (pe.entry(), pe.architecture(), image_base, sections)
            }
            File::Pe64(pe) => {
                let sections = Self::extract_sections(&pe)?;
                let image_base = pe.nt_headers().optional_header.image_base.get(LittleEndian);
                (pe.entry(), pe.architecture(), image_base, sections)
            }
            _ => return Err("Not a valid PE file"),
        };

        Ok(PeFile {
            entry_point,
            architecture,
            image_base,
            sections,
            header_data: Vec::new(),
            pdb_name,
            pdb_guid_age,
            raw_bytes: bytes.to_vec(),
        })
    }

    fn extract_sections<'data: 'file, 'file, O: Object<'data,>>(
        object_file: &'file O,
    ) -> Result<Vec<Section>, &'static str> {
        let mut sections = Vec::new();
        for section in object_file.sections() {
            if let Ok(name) = section.name() {
                if section.size() > 0 {
                    let raw_data = match section.data() {
                        Ok(data) => data.to_vec(),
                        Err(_) => return Err("Failed to read section data"),
                    };
                    sections.push(Section {
                        name: name.to_string(),
                        virtual_address: section.address(),
                        virtual_size: section.size(),
                        raw_data,
                    });
                }
            }
        }
        Ok(sections)
    }

    // ------------------------------------------------------------------------
    // [FIX] Export Directory Parsing (with Forwarder Support)
    // ------------------------------------------------------------------------
    pub fn get_exports(&self) -> Result<Vec<ExportEntry>, &'static str> {
        let (dir_rva, dir_size) = self.get_data_directory(0)?; // 0 = Export
        if dir_rva == 0 { return Ok(Vec::new()); }

        let dir_offset = self.rva_to_offset(dir_rva).ok_or("Invalid Export RVA")?;
        let data = &self.raw_bytes;

        // IMAGE_EXPORT_DIRECTORY structure reading
        // let name_rva = u32::from_le_bytes(data[dir_offset+12..dir_offset+16].try_into().unwrap());
        let _base = u32::from_le_bytes(data[dir_offset+16..dir_offset+20].try_into().unwrap());
        let num_funcs = u32::from_le_bytes(data[dir_offset+20..dir_offset+24].try_into().unwrap());
        let num_names = u32::from_le_bytes(data[dir_offset+24..dir_offset+28].try_into().unwrap());
        let addr_table_rva = u32::from_le_bytes(data[dir_offset+28..dir_offset+32].try_into().unwrap());
        let name_table_rva = u32::from_le_bytes(data[dir_offset+32..dir_offset+36].try_into().unwrap());
        let ordinal_table_rva = u32::from_le_bytes(data[dir_offset+36..dir_offset+40].try_into().unwrap());

        let mut exports = Vec::new();
        let addr_offset = self.rva_to_offset(addr_table_rva).ok_or("Invalid Address Table RVA")?;
        let name_offset = self.rva_to_offset(name_table_rva).ok_or("Invalid Name Table RVA")?;
        let ordinal_offset = self.rva_to_offset(ordinal_table_rva).ok_or("Invalid Ordinal Table RVA")?;

        // 이름이 있는 함수들 먼저 매핑
        let mut name_map: HashMap<u16, String> = HashMap::new();
        for i in 0..num_names {
            let name_rva_ptr = name_offset + (i as usize * 4);
            let name_ptr_rva = u32::from_le_bytes(data[name_rva_ptr..name_rva_ptr+4].try_into().unwrap());
            let name_str_offset = self.rva_to_offset(name_ptr_rva).ok_or("Invalid Name String RVA")?;
            let name = self.read_cstring(name_str_offset);

            let ord_ptr = ordinal_offset + (i as usize * 2);
            let ordinal = u16::from_le_bytes(data[ord_ptr..ord_ptr+2].try_into().unwrap());
            name_map.insert(ordinal, name);
        }

        // 전체 함수 테이블 순회
        for i in 0..num_funcs {
            let func_rva_ptr = addr_offset + (i as usize * 4);
            let func_rva = u32::from_le_bytes(data[func_rva_ptr..func_rva_ptr+4].try_into().unwrap());

            if func_rva == 0 { continue; } // Empty entry

            let ordinal = (i as u32 + _base) as u16; // [FIX] 실제 Ordinal (Index + Base)
            let name = name_map.get(&(i as u16)).cloned().unwrap_or_else(|| format!("#{}", ordinal));

            // Forwarder Check: RVA가 Export Directory 범위 안에 있는지 확인
            let mut forwarder = None;
            if func_rva >= dir_rva && func_rva < dir_rva + dir_size {
                if let Some(fwd_offset) = self.rva_to_offset(func_rva) {
                    forwarder = Some(self.read_cstring(fwd_offset));
                }
            }

            exports.push(ExportEntry {
                name,
                rva: func_rva,
                ordinal,
                forwarder,
            });
        }

        Ok(exports)
    }

    // ------------------------------------------------------------------------
    // [FIX] Import Directory Parsing (for IAT Binding)
    // ------------------------------------------------------------------------
    pub fn get_imports(&self) -> Result<Vec<ImportEntry>, &'static str> {
        let (dir_rva, _dir_size) = self.get_data_directory(1)?; // 1 = Import
        if dir_rva == 0 { return Ok(Vec::new()); }

        let mut imports = Vec::new();
        let mut dir_offset = self.rva_to_offset(dir_rva).ok_or("Invalid Import RVA")?;
        let data = &self.raw_bytes;

        loop {
            // IMAGE_IMPORT_DESCRIPTOR (20 bytes)
            let original_first_thunk = u32::from_le_bytes(data[dir_offset..dir_offset+4].try_into().unwrap());
            let _time_date = u32::from_le_bytes(data[dir_offset+4..dir_offset+8].try_into().unwrap());
            let _forwarder_chain = u32::from_le_bytes(data[dir_offset+8..dir_offset+12].try_into().unwrap());
            let name_rva = u32::from_le_bytes(data[dir_offset+12..dir_offset+16].try_into().unwrap());
            let first_thunk = u32::from_le_bytes(data[dir_offset+16..dir_offset+20].try_into().unwrap());

            if original_first_thunk == 0 && name_rva == 0 { break; } // End of Table

            let dll_name_offset = self.rva_to_offset(name_rva).ok_or("Invalid Import Name RVA")?;
            let dll_name = self.read_cstring(dll_name_offset);

            let mut functions = Vec::new();
            // ILT (Import Lookup Table)와 IAT (Import Address Table)는 병렬 구조
            // 64bit PE 파일은 8바이트 단위
            let mut thunk_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
            let mut iat_rva_curr = first_thunk;

            loop {
                let thunk_offset = self.rva_to_offset(thunk_rva).ok_or("Invalid Thunk RVA")?;
                let thunk_data = u64::from_le_bytes(data[thunk_offset..thunk_offset+8].try_into().unwrap());

                if thunk_data == 0 { break; }

                let func_name = if (thunk_data & (1 << 63)) != 0 {
                    // Ordinal Import
                    format!("#{}", thunk_data & 0xFFFF)
                } else {
                    // Name Import (Hint/Name Table RVA)
                    let name_rva = (thunk_data & 0x7FFFFFFF) as u32;
                    let name_offset = self.rva_to_offset(name_rva).ok_or("Invalid Hint/Name RVA")? + 2; // +2 for Hint
                    self.read_cstring(name_offset)
                };

                functions.push(ImportFunction {
                    name: func_name,
                    iat_rva: iat_rva_curr, // 이 로직이 IAT에 실제 주소를 적어야 하는 RVA를 제공함.
                });

                thunk_rva += 8;
                iat_rva_curr += 8;
            }

            imports.push(ImportEntry {
                dll_name,
                functions,
            });

            dir_offset += 20;
        }

        Ok(imports)
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------
    fn get_data_directory(&self, index: usize) -> Result<(u32, u32), &'static str> {
        let dos_header_e_lfanew = u32::from_le_bytes(self.raw_bytes[0x3C..0x40].try_into().unwrap()) as usize;
        // Optional Header Offset check (PE32+ 기준)
        // PE Signature (4) + File Header (20) + Optional Header Standard (24) = 48
        // Data Directories start at Offset 112 (0x70) inside Optional Header for PE32+
        // Standard Optional Header starts at e_lfanew + 24
        let opt_header_offset = dos_header_e_lfanew + 24;
        let data_dir_offset = opt_header_offset + 112 + (index * 8);

        if data_dir_offset + 8 > self.raw_bytes.len() {
            return Err("Data Directory out of bounds");
        }

        let rva = u32::from_le_bytes(self.raw_bytes[data_dir_offset..data_dir_offset+4].try_into().unwrap());
        let size = u32::from_le_bytes(self.raw_bytes[data_dir_offset+4..data_dir_offset+8].try_into().unwrap());
        Ok((rva, size))
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            // [FIX] Convert section VA to RVA by subtracting image_base
            let section_rva = (section.virtual_address - self.image_base) as u32;
            let start = section_rva;
            let end = start + section.virtual_size as u32;
            
            if rva >= start && rva < end {
                return self.find_file_offset(rva);
            }
        }
        None
    }

    fn find_file_offset(&self, rva: u32) -> Option<usize> {
        let e_lfanew = u32::from_le_bytes(self.raw_bytes[0x3C..0x40].try_into().unwrap()) as usize;
        let num_sections = u16::from_le_bytes(self.raw_bytes[e_lfanew+6..e_lfanew+8].try_into().unwrap()) as usize;
        let opt_size = u16::from_le_bytes(self.raw_bytes[e_lfanew+20..e_lfanew+22].try_into().unwrap()) as usize;
        
        let mut sect_ptr = e_lfanew + 24 + opt_size;
        
        for _ in 0..num_sections {
            let v_addr = u32::from_le_bytes(self.raw_bytes[sect_ptr+12..sect_ptr+16].try_into().unwrap());
            let v_size = u32::from_le_bytes(self.raw_bytes[sect_ptr+8..sect_ptr+12].try_into().unwrap());
            let r_ptr = u32::from_le_bytes(self.raw_bytes[sect_ptr+20..sect_ptr+24].try_into().unwrap());
            let r_size = u32::from_le_bytes(self.raw_bytes[sect_ptr+16..sect_ptr+20].try_into().unwrap());
            
            // [FIX] Use raw_size and virtual_size combined for better matching
            let effective_v_size = if v_size > 0 { v_size } else { r_size };
            
            if rva >= v_addr && rva < v_addr + effective_v_size {
                let delta = rva - v_addr;
                return Some((r_ptr + delta) as usize);
            }
            sect_ptr += 40;
        }
        
        // RVA가 헤더 영역에 있는 경우
        if rva < 4096 {
            return Some(rva as usize);
        }

        None
    }

    fn read_cstring(&self, offset: usize) -> String {
        let mut end = offset;
        while end < self.raw_bytes.len() && self.raw_bytes[end] != 0 {
            end += 1;
        }
        String::from_utf8_lossy(&self.raw_bytes[offset..end]).to_string()
    }

    // 기존 Relocation 함수 유지
    pub fn apply_relocation(
        &self,
        vm: &mut crate::vm::Vm,
        p_base: u64,
        v_new: u64,
    ) -> Result<(), &'static str> {
        let delta = v_new.wrapping_sub(self.image_base);
        if delta == 0 { return Ok(()); }

        let reloc_section = self.sections.iter()
            .find(|s| s.name == ".reloc")
            .ok_or("Relocation failed: No .reloc section")?;

        let data = &reloc_section.raw_data;
        let mut offset = 0;

        while offset + 8 <= data.len() {
            let page_rva = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap());
            let block_size = u32::from_le_bytes(data[offset+4..offset+8].try_into().unwrap());

            if block_size == 0 { break; }

            let entry_count = (block_size - 8) / 2;
            for i in 0..entry_count {
                let entry_pos = offset + 8 + (i as usize * 2);
                if entry_pos + 2 > data.len() { break; }

                let entry = u16::from_le_bytes(data[entry_pos..entry_pos+2].try_into().unwrap());
                let reloc_type = entry >> 12;
                let reloc_offset = entry & 0x0FFF;

                if reloc_type == 10 { // IMAGE_REL_BASED_DIR64
                    let target_rva = page_rva as u64 + reloc_offset as u64;
                    let target_paddr = p_base + target_rva;

                    unsafe {
                        if (target_paddr as usize + 8) <= crate::vm::MEM_SIZE {
                            let ptr = vm.mem_ptr.add(target_paddr as usize) as *mut u64;
                            let current_ptr = std::ptr::read_unaligned(ptr);
                            let new_ptr = current_ptr.wrapping_add(delta);
                            std::ptr::write_unaligned(ptr, new_ptr);
                        }
                    }
                }
            }
            offset += block_size as usize;
        }
        Ok(())
    }
}

impl fmt::Display for PeFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PE File Info (Base: 0x{:x})", self.image_base)
    }
}