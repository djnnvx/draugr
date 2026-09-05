package elf

import "core:encoding/json"
import "core:fmt"

Json_Symbol :: struct {
	name  : string,
	value : u64,
	size  : u64,
	bind  : string,
	type  : string,
	shndx : u16,
}

Json_Section :: struct {
	index  : int,
	name   : string,
	type   : string,
	addr   : u64,
	offset : u64,
	size   : u64,
	flags  : u64,
}

Json_Segment :: struct {
	type   : string,
	flags  : string,
	offset : u64,
	vaddr  : u64,
	paddr  : u64,
	filesz : u64,
	memsz  : u64,
	align  : u64,
}

Json_Dyn :: struct {
	tag   : string,
	value : u64,
	name  : string,
}

Json_Reloc :: struct {
	offset : u64,
	type   : string,
	addend : i64,
	symbol : string,
	source : string,
}

Json_Checksec :: struct {
	relro       : string,
	nx          : string,
	pie         : string,
	canary      : bool,
	textrel     : bool,
	rwx_segment : bool,
	rpath       : string,
	runpath     : string,
	stripped    : bool,
	fortified   : int,
	fortifiable : int,
	partial     : int,
}

Json_Dump :: struct {
	class           : int,
	endian          : string,
	type            : string,
	machine         : string,
	entry           : u64,
	flags           : u32,
	pie             : bool,
	is_dynamic      : bool,
	interp_offset   : u64,
	soname          : string,
	rpath           : string,
	runpath         : string,
	needed          : []string,
	segments        : []Json_Segment,
	sections        : []Json_Section,
	dynamic_entries : []Json_Dyn,
	symbols         : []Json_Symbol,
	dyn_symbols     : []Json_Symbol,
	relocations     : []Json_Reloc,
	got             : map[string]u64,
	checksec        : Json_Checksec,
}

build_json_dump :: proc(info: ^ELF_Info, allocator := context.allocator) -> Json_Dump {
	segments := make([]Json_Segment, len(info.program_hdrs), allocator)
	for ph, i in info.program_hdrs {
		segments[i] = Json_Segment{
			type   = segment_type_str(ph.type),
			flags  = flags_to_str(ph.flags),
			offset = ph.offset,
			vaddr  = ph.vaddr,
			paddr  = ph.paddr,
			filesz = ph.filesz,
			memsz  = ph.memsz,
			align  = ph.align,
		}
	}

	sections := make([]Json_Section, len(info.section_hdrs), allocator)
	for shdr, i in info.section_hdrs {
		sections[i] = Json_Section{
			index  = i,
			name   = get_section_name(info, shdr),
			type   = section_type_str(shdr.type),
			addr   = shdr.addr,
			offset = shdr.offset,
			size   = shdr.size,
			flags  = shdr.flags,
		}
	}

	dyn := make([]Json_Dyn, len(info.dyn_entries), allocator)
	for e, i in info.dyn_entries {
		dyn[i] = Json_Dyn{tag = dyn_tag_str(e.tag), value = e.val, name = dyn_string(info, e)}
	}

	relocs := make([]Json_Reloc, len(info.relocs), allocator)
	got := make(map[string]u64, allocator)
	for r, i in info.relocs {
		relocs[i] = Json_Reloc{
			offset = r.offset,
			type   = reloc_type_str(info.header.machine, r.type),
			addend = r.addend,
			symbol = r.sym_name,
			source = r.source,
		}
		if is_jump_slot(info.header.machine, r.type) && r.sym_name != "" {
			got[r.sym_name] = r.offset
		}
	}

	c := checksec(info)

	return Json_Dump{
		class           = 64 if info.is_64bit else 32,
		endian          = "little" if info.header.data == ELF_DATA_LSB else "big",
		type            = type_to_str(info.header.type),
		machine         = machine_to_str(info.header.machine),
		entry           = info.header.entry,
		flags           = info.header.flags,
		pie             = info.is_pie,
		is_dynamic      = info.is_dynamic,
		interp_offset   = info.interp_offset,
		soname          = info.soname,
		rpath           = info.rpath,
		runpath         = info.runpath,
		needed          = info.needed[:],
		segments        = segments,
		sections        = sections,
		dynamic_entries = dyn,
		symbols         = to_json_symbols(info.symbols[:], allocator),
		dyn_symbols     = to_json_symbols(info.dyn_symbols[:], allocator),
		relocations     = relocs,
		got             = got,
		checksec        = Json_Checksec{
			relro       = relro_str(c.relro),
			nx          = nx_str(c.nx),
			pie         = pie_str(c.pie),
			canary      = c.canary,
			textrel     = c.textrel,
			rwx_segment = c.rwx_segment,
			rpath       = c.rpath,
			runpath     = c.runpath,
			stripped    = c.stripped,
			fortified   = c.fortified,
			fortifiable = c.fortifiable,
			partial     = c.partial,
		},
	}
}

to_json_symbols :: proc(syms: []Symbol, allocator := context.allocator) -> []Json_Symbol {
	out := make([]Json_Symbol, len(syms), allocator)
	for sym, i in syms {
		out[i] = Json_Symbol{
			name  = sym.name,
			value = sym.value,
			size  = sym.size,
			bind  = symbol_bind_str(sym.bind),
			type  = symbol_type_str(sym.type),
			shndx = sym.shndx,
		}
	}
	return out
}

print_json :: proc(info: ^ELF_Info) -> string {
	defer free_all(context.temp_allocator)

	dump := build_json_dump(info, context.temp_allocator)
	data, err := json.marshal(dump, {pretty = true, use_spaces = true}, context.temp_allocator)
	if err != nil {
		return fmt.tprintf("json marshal failed: %v", err)
	}

	fmt.println(string(data))
	return ""
}
