package elf

load :: proc(data: []u8) -> (ELF_Info, string) {
	info: ELF_Info
	
	header, err := parse_header(data)
	if err != "" {
		return info, err
	}
	info.header = header
	info.is_64bit = header.class == ELF_CLASS_64
	info.is_pie = header.type == ET_DYN
	info.is_dynamic = false
	
	info.program_hdrs = make([dynamic]Program_Header)
	info.section_hdrs = make([dynamic]Section_Header)
	info.symbols = make([dynamic]Symbol)
	info.dyn_symbols = make([dynamic]Symbol)

	// Sections first: PN_XNUM resolves e_phnum through section[0].
	parse_section_headers(data, &info)
	parse_program_headers(data, &info)
	parse_symbols(data, &info)
	
	return info, ""
}

destroy :: proc(info: ^ELF_Info) {
	delete(info.program_hdrs)
	delete(info.section_hdrs)
	delete(info.symbols)
	delete(info.dyn_symbols)
}

get_section_name :: proc(info: ^ELF_Info, shdr: Section_Header) -> string {
	if info.shstrtab == nil {
		return "<unknown>"
	}
	if len(info.shstrtab) == 0 {
		return "<unknown>"
	}
	start := int(shdr.name)
	for i := start; i < len(info.shstrtab); i += 1 {
		if info.shstrtab[i] == 0 {
			return string(info.shstrtab[start:i])
		}
	}
	return ""
}

get_symbol_name :: proc(strtab: []u8, name_offset: u32) -> string {
	if strtab == nil {
		return ""
	}
	if len(strtab) == 0 {
		return ""
	}
	start := int(name_offset)
	if start >= len(strtab) {
		return ""
	}
	for i := start; i < len(strtab); i += 1 {
		if strtab[i] == 0 {
			return string(strtab[start:i])
		}
	}
	return ""
}

PHDR_SIZE_64 :: 56
PHDR_SIZE_32 :: 32
SHDR_SIZE_64 :: 64
SHDR_SIZE_32 :: 40
SYM_SIZE_64  :: 24
SYM_SIZE_32  :: 16

read_program_header :: proc(data: []u8, offset: int, is_64bit: bool, order: Byte_Order) -> Program_Header {
	ph: Program_Header
	if is_64bit {
		ph.type = read_u32(data, offset, order)
		ph.flags = u64(read_u32(data, offset + 4, order))
		ph.offset = read_u64(data, offset + 8, order)
		ph.vaddr = read_u64(data, offset + 16, order)
		ph.paddr = read_u64(data, offset + 24, order)
		ph.filesz = read_u64(data, offset + 32, order)
		ph.memsz = read_u64(data, offset + 40, order)
		ph.align = read_u64(data, offset + 48, order)
	} else {
		ph.type = read_u32(data, offset, order)
		ph.offset = u64(read_u32(data, offset + 4, order))
		ph.vaddr = u64(read_u32(data, offset + 8, order))
		ph.paddr = u64(read_u32(data, offset + 12, order))
		ph.filesz = u64(read_u32(data, offset + 16, order))
		ph.memsz = u64(read_u32(data, offset + 20, order))
		ph.flags = u64(read_u32(data, offset + 24, order))
		ph.align = u64(read_u32(data, offset + 28, order))
	}
	return ph
}

parse_program_headers :: proc(data: []u8, info: ^ELF_Info) {
	header := info.header
	is_64bit := info.is_64bit
	order := byte_order(info.header)

	if !in_bounds(data, header.phoff, 0) { return }

	min_size := PHDR_SIZE_64 if is_64bit else PHDR_SIZE_32
	entsize := int(header.phentsize)
	if entsize < min_size { entsize = min_size }

	// PN_XNUM: the real segment count lives in section[0].sh_info.
	phnum := u64(header.phnum)
	if phnum == PN_XNUM && len(info.section_hdrs) > 0 {
		phnum = u64(info.section_hdrs[0].info)
	}

	offset := int(header.phoff)
	for i := u64(0); i < phnum; i += 1 {
		if offset + min_size > len(data) { break }

		ph := read_program_header(data, offset, is_64bit, order)
		offset += entsize
		append(&info.program_hdrs, ph)

		if ph.type == PT_INTERP {
			info.interp_offset = ph.offset
			info.is_dynamic = true
		}
		if ph.type == PT_DYNAMIC {
			info.is_dynamic = true
		}
	}
}

read_section_header :: proc(data: []u8, offset: int, is_64bit: bool, order: Byte_Order) -> Section_Header {
	sh: Section_Header
	if is_64bit {
		sh.name = read_u32(data, offset, order)
		sh.type = read_u32(data, offset + 4, order)
		sh.flags = read_u64(data, offset + 8, order)
		sh.addr = read_u64(data, offset + 16, order)
		sh.offset = read_u64(data, offset + 24, order)
		sh.size = read_u64(data, offset + 32, order)
		sh.link = read_u32(data, offset + 40, order)
		sh.info = read_u32(data, offset + 44, order)
		sh.addralign = read_u64(data, offset + 48, order)
		sh.entsize = read_u64(data, offset + 56, order)
	} else {
		sh.name = read_u32(data, offset, order)
		sh.type = read_u32(data, offset + 4, order)
		sh.flags = u64(read_u32(data, offset + 8, order))
		sh.addr = u64(read_u32(data, offset + 12, order))
		sh.offset = u64(read_u32(data, offset + 16, order))
		sh.size = u64(read_u32(data, offset + 20, order))
		sh.link = read_u32(data, offset + 24, order)
		sh.info = read_u32(data, offset + 28, order)
		sh.addralign = u64(read_u32(data, offset + 32, order))
		sh.entsize = u64(read_u32(data, offset + 36, order))
	}
	return sh
}

parse_section_headers :: proc(data: []u8, info: ^ELF_Info) {
	header := info.header
	is_64bit := info.is_64bit
	order := byte_order(info.header)

	if !in_bounds(data, header.shoff, 0) { return }

	min_size := SHDR_SIZE_64 if is_64bit else SHDR_SIZE_32
	entsize := int(header.shentsize)
	if entsize < min_size { entsize = min_size }

	start := int(header.shoff)
	shnum := u64(header.shnum)
	shstrndx := u64(header.shstrndx)

	// e_shnum == 0 and e_shstrndx == SHN_XINDEX are escape hatches: the real
	// values live in section[0].sh_size and section[0].sh_link.
	if shnum == 0 || shstrndx == SHN_XINDEX {
		if start + min_size > len(data) { return }
		sh0 := read_section_header(data, start, is_64bit, order)
		if shnum == 0 { shnum = sh0.size }
		if shstrndx == SHN_XINDEX { shstrndx = u64(sh0.link) }
	}

	offset := start
	for i := u64(0); i < shnum; i += 1 {
		if offset + min_size > len(data) { break }
		append(&info.section_hdrs, read_section_header(data, offset, is_64bit, order))
		offset += entsize
	}

	if shstrndx < u64(len(info.section_hdrs)) {
		shstrtab_hdr := info.section_hdrs[shstrndx]
		if shstrtab_hdr.type != SHT_NULL && in_bounds(data, shstrtab_hdr.offset, shstrtab_hdr.size) {
			s := int(shstrtab_hdr.offset)
			info.shstrtab = data[s : s + int(shstrtab_hdr.size)]
		}
	}
}

parse_symbols :: proc(data: []u8, info: ^ELF_Info) {
	for shdr in info.section_hdrs {
		if shdr.type != SHT_SYMTAB && shdr.type != SHT_DYNSYM {
			continue
		}
		strtab_idx := int(shdr.link)
		if strtab_idx >= len(info.section_hdrs) { continue }

		strtab_hdr := info.section_hdrs[strtab_idx]
		if !in_bounds(data, strtab_hdr.offset, strtab_hdr.size) { continue }
		if !in_bounds(data, shdr.offset, shdr.size) { continue }

		strtab_start := int(strtab_hdr.offset)
		strtab := data[strtab_start : strtab_start + int(strtab_hdr.size)]

		if shdr.type == SHT_DYNSYM {
			info.dynstr = strtab
		} else {
			info.strtab = strtab
		}

		is_64bit := info.is_64bit
		order := byte_order(info.header)
		offset := int(shdr.offset)

		min_size := u64(SYM_SIZE_64) if is_64bit else u64(SYM_SIZE_32)
		entsize := shdr.entsize
		if entsize < min_size { entsize = min_size }

		num_symbols := shdr.size / entsize
		for j := u64(0); j < num_symbols; j += 1 {
			sym: Symbol
			name_off: u32
			sym_info: u8
			next := offset + int(entsize)

			if is_64bit {
				if offset + SYM_SIZE_64 > len(data) { break }
				name_off = read_u32(data, offset, order)
				sym_info = data[offset + 4]
				sym.shndx = read_u16(data, offset + 6, order)
				sym.value = read_u64(data, offset + 8, order)
				sym.size = read_u64(data, offset + 16, order)
			} else {
				if offset + SYM_SIZE_32 > len(data) { break }
				name_off = read_u32(data, offset, order)
				sym.value = u64(read_u32(data, offset + 4, order))
				sym.size = u64(read_u32(data, offset + 8, order))
				sym_info = data[offset + 12]
				sym.shndx = read_u16(data, offset + 14, order)
			}
			offset = next

			sym.name = get_symbol_name(strtab, name_off)
			sym.bind = sym_info >> 4
			sym.type = sym_info & 0xf

			if shdr.type == SHT_DYNSYM {
				append(&info.dyn_symbols, sym)
			} else {
				append(&info.symbols, sym)
			}
		}
	}
}
