package elf

import "core:fmt"

Reloc_Source :: enum {
	Rel,
	Rela,
	Relr,
}

Reloc :: struct {
	offset   : u64,
	addend   : i64,
	sym      : u32,
	type     : u32,
	sym_name : string,
	source   : string,
	kind     : Reloc_Source,
}

REL_SIZE_64  :: 16
RELA_SIZE_64 :: 24
REL_SIZE_32  :: 8
RELA_SIZE_32 :: 12

parse_relocs :: proc(data: []u8, info: ^ELF_Info) {
	if parse_relocs_from_sections(data, info) {
		return
	}
	parse_relocs_from_dynamic(data, info)
}

parse_relocs_from_sections :: proc(data: []u8, info: ^ELF_Info) -> bool {
	found := false
	for shdr in info.section_hdrs {
		kind: Reloc_Source
		switch shdr.type {
		case SHT_REL:  kind = .Rel
		case SHT_RELA: kind = .Rela
		case SHT_RELR: kind = .Relr
		case:          continue
		}
		if !in_bounds(data, shdr.offset, shdr.size) || shdr.size == 0 {
			continue
		}
		found = true
		name := get_section_name(info, shdr)
		syms := symbols_for_link(info, shdr.link)
		read_reloc_table(data, info, shdr.offset, shdr.size, kind, name, syms)
	}
	return found
}

symbols_for_link :: proc(info: ^ELF_Info, link: u32) -> []Symbol {
	if int(link) < len(info.section_hdrs) && info.section_hdrs[link].type == SHT_SYMTAB {
		return info.symbols[:]
	}
	return info.dyn_symbols[:]
}

parse_relocs_from_dynamic :: proc(data: []u8, info: ^ELF_Info) {
	syms := info.dyn_symbols[:]

	if addr, ok := dyn_val(info, DT_RELA); ok {
		if size, ok2 := dyn_val(info, DT_RELASZ); ok2 {
			read_dynamic_table(data, info, addr, size, .Rela, "DT_RELA", syms)
		}
	}
	if addr, ok := dyn_val(info, DT_REL); ok {
		if size, ok2 := dyn_val(info, DT_RELSZ); ok2 {
			read_dynamic_table(data, info, addr, size, .Rel, "DT_REL", syms)
		}
	}
	if addr, ok := dyn_val(info, DT_RELR); ok {
		if size, ok2 := dyn_val(info, DT_RELRSZ); ok2 {
			read_dynamic_table(data, info, addr, size, .Relr, "DT_RELR", syms)
		}
	}
	if addr, ok := dyn_val(info, DT_JMPREL); ok {
		if size, ok2 := dyn_val(info, DT_PLTRELSZ); ok2 {
			kind: Reloc_Source = .Rela
			if pltrel, ok3 := dyn_val(info, DT_PLTREL); ok3 && pltrel == DT_REL {
				kind = .Rel
			}
			read_dynamic_table(data, info, addr, size, kind, "DT_JMPREL", syms)
		}
	}
}

read_dynamic_table :: proc(data: []u8, info: ^ELF_Info, vaddr, size: u64, kind: Reloc_Source, source: string, syms: []Symbol) {
	off, ok := vaddr_to_offset(info, vaddr)
	if !ok || !in_bounds(data, off, size) {
		return
	}
	read_reloc_table(data, info, off, size, kind, source, syms)
}

read_reloc_table :: proc(data: []u8, info: ^ELF_Info, offset, size: u64, kind: Reloc_Source, source: string, syms: []Symbol) {
	if kind == .Relr {
		read_relr_table(data, info, offset, size, source)
		return
	}

	order := byte_order(info.header)
	is64 := info.is_64bit

	entsize := u64(0)
	switch {
	case kind == .Rela && is64:  entsize = RELA_SIZE_64
	case kind == .Rela && !is64: entsize = RELA_SIZE_32
	case kind == .Rel && is64:   entsize = REL_SIZE_64
	case:                        entsize = REL_SIZE_32
	}

	for pos := offset; pos + entsize <= offset + size; pos += entsize {
		r: Reloc
		r.kind = kind
		r.source = source

		raw_info: u64
		if is64 {
			r.offset = read_u64(data, int(pos), order)
			raw_info = read_u64(data, int(pos + 8), order)
			r.sym = u32(raw_info >> 32)
			r.type = u32(raw_info & 0xffffffff)
			if kind == .Rela {
				r.addend = i64(read_u64(data, int(pos + 16), order))
			}
		} else {
			r.offset = u64(read_u32(data, int(pos), order))
			raw_info = u64(read_u32(data, int(pos + 4), order))
			r.sym = u32(raw_info >> 8)
			r.type = u32(raw_info & 0xff)
			if kind == .Rela {
				r.addend = i64(i32(read_u32(data, int(pos + 8), order)))
			}
		}

		if int(r.sym) < len(syms) {
			r.sym_name = syms[r.sym].name
		}
		append(&info.relocs, r)
	}
}

// RELR packs relative relocations: an even word is an address, an odd word is a
// bitmap of the words that follow it.
read_relr_table :: proc(data: []u8, info: ^ELF_Info, offset, size: u64, source: string) {
	order := byte_order(info.header)
	is64 := info.is_64bit
	word := u64(8) if is64 else u64(4)
	rel_type := relative_reloc_type(info.header.machine)

	base := u64(0)
	for pos := offset; pos + word <= offset + size; pos += word {
		entry := read_u64(data, int(pos), order) if is64 else u64(read_u32(data, int(pos), order))

		if entry & 1 == 0 {
			append(&info.relocs, Reloc{
				offset = entry, type = rel_type, source = source, kind = .Relr,
			})
			base = entry + word
			continue
		}

		bits := entry >> 1
		for i := u64(0); bits != 0; i += 1 {
			if bits & 1 != 0 {
				append(&info.relocs, Reloc{
					offset = base + i * word, type = rel_type, source = source, kind = .Relr,
				})
			}
			bits >>= 1
		}
		base += (word * 8 - 1) * word
	}
}

R_X86_64_RELATIVE  :: 8
R_386_RELATIVE     :: 8
R_AARCH64_RELATIVE :: 1027
R_ARM_RELATIVE     :: 23
R_RISCV_RELATIVE   :: 3

relative_reloc_type :: proc(machine: u16) -> u32 {
	switch machine {
	case EM_X86_64:  return R_X86_64_RELATIVE
	case EM_386:     return R_386_RELATIVE
	case EM_AARCH64: return R_AARCH64_RELATIVE
	case EM_ARM:     return R_ARM_RELATIVE
	case EM_RISCV:   return R_RISCV_RELATIVE
	}
	return 0
}

is_jump_slot :: proc(machine: u16, type: u32) -> bool {
	switch machine {
	case EM_X86_64:  return type == 7
	case EM_386:     return type == 7
	case EM_AARCH64: return type == 1026
	case EM_ARM:     return type == 22
	case EM_RISCV:   return type == 5
	}
	return false
}

reloc_type_str :: proc(machine: u16, type: u32) -> string {
	switch machine {
	case EM_X86_64:
		switch type {
		case 0:  return "R_X86_64_NONE"
		case 1:  return "R_X86_64_64"
		case 2:  return "R_X86_64_PC32"
		case 3:  return "R_X86_64_GOT32"
		case 4:  return "R_X86_64_PLT32"
		case 5:  return "R_X86_64_COPY"
		case 6:  return "R_X86_64_GLOB_DAT"
		case 7:  return "R_X86_64_JUMP_SLOT"
		case 8:  return "R_X86_64_RELATIVE"
		case 9:  return "R_X86_64_GOTPCREL"
		case 16: return "R_X86_64_DTPMOD64"
		case 17: return "R_X86_64_DTPOFF64"
		case 18: return "R_X86_64_TPOFF64"
		case 37: return "R_X86_64_IRELATIVE"
		case 41: return "R_X86_64_TLSDESC"
		}
	case EM_386:
		switch type {
		case 0:  return "R_386_NONE"
		case 1:  return "R_386_32"
		case 2:  return "R_386_PC32"
		case 5:  return "R_386_COPY"
		case 6:  return "R_386_GLOB_DAT"
		case 7:  return "R_386_JMP_SLOT"
		case 8:  return "R_386_RELATIVE"
		case 42: return "R_386_IRELATIVE"
		}
	case EM_AARCH64:
		switch type {
		case 0:    return "R_AARCH64_NONE"
		case 257:  return "R_AARCH64_ABS64"
		case 1024: return "R_AARCH64_COPY"
		case 1025: return "R_AARCH64_GLOB_DAT"
		case 1026: return "R_AARCH64_JUMP_SLOT"
		case 1027: return "R_AARCH64_RELATIVE"
		case 1032: return "R_AARCH64_IRELATIVE"
		}
	case EM_ARM:
		switch type {
		case 0:   return "R_ARM_NONE"
		case 2:   return "R_ARM_ABS32"
		case 20:  return "R_ARM_COPY"
		case 21:  return "R_ARM_GLOB_DAT"
		case 22:  return "R_ARM_JUMP_SLOT"
		case 23:  return "R_ARM_RELATIVE"
		case 160: return "R_ARM_IRELATIVE"
		}
	case EM_RISCV:
		switch type {
		case 0:  return "R_RISCV_NONE"
		case 1:  return "R_RISCV_32"
		case 2:  return "R_RISCV_64"
		case 3:  return "R_RISCV_RELATIVE"
		case 4:  return "R_RISCV_COPY"
		case 5:  return "R_RISCV_JUMP_SLOT"
		case 58: return "R_RISCV_IRELATIVE"
		}
	}
	return fmt.tprintf("%d", type)
}
