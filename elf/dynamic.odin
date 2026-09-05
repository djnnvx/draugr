package elf

import "core:fmt"

DT_NULL         :: 0
DT_NEEDED       :: 1
DT_PLTRELSZ     :: 2
DT_PLTGOT       :: 3
DT_HASH         :: 4
DT_STRTAB       :: 5
DT_SYMTAB       :: 6
DT_RELA         :: 7
DT_RELASZ       :: 8
DT_RELAENT      :: 9
DT_STRSZ        :: 10
DT_SYMENT       :: 11
DT_INIT         :: 12
DT_FINI         :: 13
DT_SONAME       :: 14
DT_RPATH        :: 15
DT_SYMBOLIC     :: 16
DT_REL          :: 17
DT_RELSZ        :: 18
DT_RELENT       :: 19
DT_PLTREL       :: 20
DT_DEBUG        :: 21
DT_TEXTREL      :: 22
DT_JMPREL       :: 23
DT_BIND_NOW     :: 24
DT_INIT_ARRAY   :: 25
DT_FINI_ARRAY   :: 26
DT_INIT_ARRAYSZ :: 27
DT_FINI_ARRAYSZ :: 28
DT_RUNPATH      :: 29
DT_FLAGS        :: 30

DT_PREINIT_ARRAY   :: 32
DT_PREINIT_ARRAYSZ :: 33
DT_SYMTAB_SHNDX    :: 34
DT_RELRSZ          :: 35
DT_RELR            :: 36
DT_RELRENT         :: 37

DT_GNU_HASH     :: 0x6ffffef5
DT_TLSDESC_PLT  :: 0x6ffffef6
DT_TLSDESC_GOT  :: 0x6ffffef7
DT_VERSYM       :: 0x6ffffff0
DT_RELACOUNT    :: 0x6ffffff9
DT_RELCOUNT     :: 0x6ffffffa
DT_FLAGS_1      :: 0x6ffffffb
DT_VERDEF       :: 0x6ffffffc
DT_VERDEFNUM    :: 0x6ffffffd
DT_VERNEED      :: 0x6ffffffe
DT_VERNEEDNUM   :: 0x6fffffff
DT_AUXILIARY    :: 0x7ffffffd
DT_FILTER       :: 0x7fffffff

DF_TEXTREL  :: 0x4
DF_BIND_NOW :: 0x8

DF_1_NOW :: 0x1
DF_1_PIE :: 0x08000000

DYN_SIZE_64 :: 16
DYN_SIZE_32 :: 8

Dyn_Entry :: struct {
	tag : u64,
	val : u64,
}

dyn_tag_str :: proc(tag: u64) -> string {
	switch tag {
	case DT_NULL:         return "NULL"
	case DT_NEEDED:       return "NEEDED"
	case DT_PLTRELSZ:     return "PLTRELSZ"
	case DT_PLTGOT:       return "PLTGOT"
	case DT_HASH:         return "HASH"
	case DT_STRTAB:       return "STRTAB"
	case DT_SYMTAB:       return "SYMTAB"
	case DT_RELA:         return "RELA"
	case DT_RELASZ:       return "RELASZ"
	case DT_RELAENT:      return "RELAENT"
	case DT_STRSZ:        return "STRSZ"
	case DT_SYMENT:       return "SYMENT"
	case DT_INIT:         return "INIT"
	case DT_FINI:         return "FINI"
	case DT_SONAME:       return "SONAME"
	case DT_RPATH:        return "RPATH"
	case DT_SYMBOLIC:     return "SYMBOLIC"
	case DT_REL:          return "REL"
	case DT_RELSZ:        return "RELSZ"
	case DT_RELENT:       return "RELENT"
	case DT_PLTREL:       return "PLTREL"
	case DT_DEBUG:        return "DEBUG"
	case DT_TEXTREL:      return "TEXTREL"
	case DT_JMPREL:       return "JMPREL"
	case DT_BIND_NOW:     return "BIND_NOW"
	case DT_INIT_ARRAY:   return "INIT_ARRAY"
	case DT_FINI_ARRAY:   return "FINI_ARRAY"
	case DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ"
	case DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ"
	case DT_RUNPATH:      return "RUNPATH"
	case DT_FLAGS:        return "FLAGS"
	case DT_PREINIT_ARRAY:   return "PREINIT_ARRAY"
	case DT_PREINIT_ARRAYSZ: return "PREINIT_ARRAYSZ"
	case DT_SYMTAB_SHNDX:    return "SYMTAB_SHNDX"
	case DT_RELRSZ:          return "RELRSZ"
	case DT_RELR:            return "RELR"
	case DT_RELRENT:         return "RELRENT"
	case DT_GNU_HASH:        return "GNU_HASH"
	case DT_TLSDESC_PLT:     return "TLSDESC_PLT"
	case DT_TLSDESC_GOT:     return "TLSDESC_GOT"
	case DT_VERSYM:          return "VERSYM"
	case DT_RELACOUNT:       return "RELACOUNT"
	case DT_RELCOUNT:        return "RELCOUNT"
	case DT_FLAGS_1:         return "FLAGS_1"
	case DT_VERDEF:          return "VERDEF"
	case DT_VERDEFNUM:       return "VERDEFNUM"
	case DT_VERNEED:         return "VERNEED"
	case DT_VERNEEDNUM:      return "VERNEEDNUM"
	case DT_AUXILIARY:       return "AUXILIARY"
	case DT_FILTER:          return "FILTER"
	}
	return fmt.tprintf("0x%x", tag)
}

dyn_is_string_tag :: proc(tag: u64) -> bool {
	switch tag {
	case DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_AUXILIARY, DT_FILTER:
		return true
	}
	return false
}

dyn_string :: proc(info: ^ELF_Info, e: Dyn_Entry) -> string {
	if !dyn_is_string_tag(e.tag) || info.dynstr == nil || e.val > u64(max(u32)) {
		return ""
	}
	return get_symbol_name(info.dynstr, u32(e.val))
}

vaddr_to_offset :: proc(info: ^ELF_Info, vaddr: u64) -> (u64, bool) {
	for ph in info.program_hdrs {
		if ph.type != PT_LOAD || ph.filesz == 0 {
			continue
		}
		if vaddr >= ph.vaddr && vaddr - ph.vaddr < ph.filesz {
			return ph.offset + (vaddr - ph.vaddr), true
		}
	}
	return 0, false
}

dyn_val :: proc(info: ^ELF_Info, tag: u64) -> (u64, bool) {
	for e in info.dyn_entries {
		if e.tag == tag {
			return e.val, true
		}
	}
	return 0, false
}

parse_dynamic :: proc(data: []u8, info: ^ELF_Info) {
	offset, size, ok := find_dynamic(info)
	if !ok || !in_bounds(data, offset, size) {
		return
	}

	order := byte_order(info.header)
	entsize := u64(DYN_SIZE_64) if info.is_64bit else u64(DYN_SIZE_32)

	for pos := offset; pos + entsize <= offset + size; pos += entsize {
		e: Dyn_Entry
		if info.is_64bit {
			e.tag = read_u64(data, int(pos), order)
			e.val = read_u64(data, int(pos + 8), order)
		} else {
			e.tag = u64(read_u32(data, int(pos), order))
			e.val = u64(read_u32(data, int(pos + 4), order))
		}
		if e.tag == DT_NULL {
			break
		}
		append(&info.dyn_entries, e)
	}

	resolve_dynamic_strings(data, info)
}

find_dynamic :: proc(info: ^ELF_Info) -> (offset: u64, size: u64, ok: bool) {
	for ph in info.program_hdrs {
		if ph.type == PT_DYNAMIC && ph.filesz > 0 {
			return ph.offset, ph.filesz, true
		}
	}
	for shdr in info.section_hdrs {
		if shdr.type == SHT_DYNAMIC && shdr.size > 0 {
			return shdr.offset, shdr.size, true
		}
	}
	return 0, 0, false
}

// DT_STRTAB is a vaddr, so this also works when section headers are stripped.
dynstr_from_dynamic :: proc(data: []u8, info: ^ELF_Info) -> []u8 {
	strtab_va, has_va := dyn_val(info, DT_STRTAB)
	strsz, has_sz := dyn_val(info, DT_STRSZ)
	if !has_va || !has_sz {
		return nil
	}
	off, ok := vaddr_to_offset(info, strtab_va)
	if !ok || !in_bounds(data, off, strsz) {
		return nil
	}
	return data[off : off + strsz]
}

resolve_dynamic_strings :: proc(data: []u8, info: ^ELF_Info) {
	strtab := dynstr_from_dynamic(data, info)
	if strtab == nil {
		strtab = info.dynstr
	}
	if strtab == nil {
		return
	}
	info.dynstr = strtab

	for e in info.dyn_entries {
		if e.val > u64(max(u32)) {
			continue
		}
		name := get_symbol_name(strtab, u32(e.val))
		switch e.tag {
		case DT_NEEDED:  append(&info.needed, name)
		case DT_SONAME:  info.soname = name
		case DT_RPATH:   info.rpath = name
		case DT_RUNPATH: info.runpath = name
		}
	}
}
