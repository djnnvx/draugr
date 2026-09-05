package analysis

import "core:fmt"
import "core:os"

import "../elf"

code_output :: proc(data: []u8, info: ^elf.ELF_Info, out_path: string) -> string {
	f, err := open_out(out_path)
	if err != "" {
		return err
	}
	defer close_out(f, out_path)

	fmt.fprintf(f, "Code Regions\n")
	fmt.fprintf(f, "============\n\n")

	print_exec_regions(f, data, info)
	print_entry_analysis(f, info)
	print_function_starts(f, data, info)

	return ""
}

print_exec_regions :: proc(f: ^os.File, data: []u8, info: ^elf.ELF_Info) {
	fmt.fprintf(f, "Executable Sections:\n")
	fmt.fprintf(f, "%-20s %-18s %-12s %-12s %s\n", "Name", "VAddr", "Offset", "Size", "Entropy")

	found := false
	for shdr in info.section_hdrs {
		if shdr.flags & elf.SHF_EXECINSTR == 0 || shdr.type == elf.SHT_NOBITS {
			continue
		}
		found = true
		fmt.fprintf(f, "%-20s 0x%016x 0x%-10x 0x%-10x %.2f\n",
			elf.get_section_name(info, shdr), shdr.addr, shdr.offset, shdr.size,
			region_entropy(data, shdr.offset, shdr.size))
	}

	if !found {
		fmt.fprintf(f, "  (no section headers, falling back to executable segments)\n")
		for ph in info.program_hdrs {
			if ph.type != elf.PT_LOAD || ph.flags & elf.PF_X == 0 {
				continue
			}
			fmt.fprintf(f, "%-20s 0x%016x 0x%-10x 0x%-10x %.2f\n",
				"PT_LOAD", ph.vaddr, ph.offset, ph.filesz,
				region_entropy(data, ph.offset, ph.filesz))
		}
	}
	fmt.fprintf(f, "\n")
}

region_entropy :: proc(data: []u8, offset: u64, size: u64) -> f64 {
	if !elf.in_bounds(data, offset, size) || size == 0 {
		return 0.0
	}
	return calculate_entropy(data[offset : offset + size])
}

print_entry_analysis :: proc(f: ^os.File, info: ^elf.ELF_Info) {
	entry := info.header.entry
	fmt.fprintf(f, "Entry Point: 0x%016x\n", entry)

	for shdr in info.section_hdrs {
		if shdr.addr != 0 && entry >= shdr.addr && entry - shdr.addr < shdr.size {
			fmt.fprintf(f, "  in section: %s\n", elf.get_section_name(info, shdr))
			break
		}
	}

	executable := false
	mapped := false
	for ph in info.program_hdrs {
		if ph.type != elf.PT_LOAD || ph.memsz == 0 {
			continue
		}
		if entry >= ph.vaddr && entry - ph.vaddr < ph.memsz {
			mapped = true
			if ph.flags & elf.PF_X != 0 {
				executable = true
			}
		}
	}

	switch {
	case !mapped:
		fmt.fprintf(f, "  WARNING: entry point is outside every PT_LOAD\n")
	case !executable:
		fmt.fprintf(f, "  WARNING: entry point is in a non-executable segment\n")
	case:
		fmt.fprintf(f, "  in an executable segment\n")
	}
	fmt.fprintf(f, "\n")
}

DW_EH_PE_OMIT :: 0xff

DW_EH_PE_ABSPTR :: 0x00
DW_EH_PE_UDATA2 :: 0x02
DW_EH_PE_UDATA4 :: 0x03
DW_EH_PE_UDATA8 :: 0x04
DW_EH_PE_SDATA2 :: 0x0a
DW_EH_PE_SDATA4 :: 0x0b
DW_EH_PE_SDATA8 :: 0x0c

DW_EH_PE_PCREL   :: 0x10
DW_EH_PE_DATAREL :: 0x30

// .eh_frame_hdr holds a sorted table of function start addresses, and it
// survives stripping.
print_function_starts :: proc(f: ^os.File, data: []u8, info: ^elf.ELF_Info) {
	hdr_vaddr, hdr_off, hdr_size, ok := find_eh_frame_hdr(info)
	if !ok || !elf.in_bounds(data, hdr_off, hdr_size) {
		fmt.fprintf(f, "Function Starts: no PT_GNU_EH_FRAME\n\n")
		return
	}

	starts, err := eh_frame_starts(data, info, hdr_vaddr, hdr_off, hdr_size)
	defer delete(starts)

	if err != "" {
		fmt.fprintf(f, "Function Starts: %s\n\n", err)
		return
	}

	fmt.fprintf(f, "Function Starts: %d (from .eh_frame_hdr)\n", len(starts))
	shown := min(len(starts), 10)
	for i := 0; i < shown; i += 1 {
		fmt.fprintf(f, "  0x%016x\n", starts[i])
	}
	if len(starts) > shown {
		fmt.fprintf(f, "  ... %d more\n", len(starts) - shown)
	}
	fmt.fprintf(f, "\n")
}

find_eh_frame_hdr :: proc(info: ^elf.ELF_Info) -> (vaddr: u64, offset: u64, size: u64, ok: bool) {
	for ph in info.program_hdrs {
		if ph.type == elf.PT_GNU_EH_FRAME && ph.filesz > 0 {
			return ph.vaddr, ph.offset, ph.filesz, true
		}
	}
	return 0, 0, 0, false
}

eh_frame_starts :: proc(data: []u8, info: ^elf.ELF_Info, hdr_vaddr, hdr_off, hdr_size: u64) -> ([dynamic]u64, string) {
	starts := make([dynamic]u64)
	order := elf.byte_order(info.header)

	buf := data[hdr_off : hdr_off + hdr_size]
	if len(buf) < 4 {
		return starts, "header too small"
	}
	if buf[0] != 1 {
		return starts, fmt.tprintf("unsupported version %d", buf[0])
	}

	frame_enc := buf[1]
	count_enc := buf[2]
	table_enc := buf[3]
	pos := 4

	if count_enc == DW_EH_PE_OMIT || table_enc == DW_EH_PE_OMIT {
		return starts, "no binary search table"
	}
	if _, e := read_encoded(buf, &pos, frame_enc, hdr_vaddr, hdr_vaddr, order, info.is_64bit); e != "" {
		return starts, e
	}
	count, cerr := read_encoded(buf, &pos, count_enc, hdr_vaddr, hdr_vaddr, order, info.is_64bit)
	if cerr != "" {
		return starts, cerr
	}

	for i := u64(0); i < count; i += 1 {
		loc, lerr := read_encoded(buf, &pos, table_enc, hdr_vaddr, hdr_vaddr, order, info.is_64bit)
		if lerr != "" {
			return starts, lerr
		}
		if _, aerr := read_encoded(buf, &pos, table_enc, hdr_vaddr, hdr_vaddr, order, info.is_64bit); aerr != "" {
			return starts, aerr
		}
		append(&starts, loc)
	}
	return starts, ""
}

read_encoded :: proc(buf: []u8, pos: ^int, enc: u8, pc_vaddr, data_vaddr: u64, order: elf.Byte_Order, is_64bit: bool) -> (u64, string) {
	base := u64(0)
	switch enc & 0x70 {
	case 0:                 base = 0
	case DW_EH_PE_PCREL:    base = pc_vaddr + u64(pos^)
	case DW_EH_PE_DATAREL:  base = data_vaddr
	case:                   return 0, fmt.tprintf("unsupported pointer application 0x%x", enc & 0x70)
	}

	format := enc & 0x0f
	if format == DW_EH_PE_ABSPTR {
		format = DW_EH_PE_UDATA8 if is_64bit else DW_EH_PE_UDATA4
	}

	value := u64(0)
	size := 0
	switch format {
	case DW_EH_PE_UDATA2: value = u64(elf.read_u16(buf, pos^, order));               size = 2
	case DW_EH_PE_UDATA4: value = u64(elf.read_u32(buf, pos^, order));               size = 4
	case DW_EH_PE_UDATA8: value = elf.read_u64(buf, pos^, order);                    size = 8
	case DW_EH_PE_SDATA2: value = u64(i64(i16(elf.read_u16(buf, pos^, order))));     size = 2
	case DW_EH_PE_SDATA4: value = u64(i64(i32(elf.read_u32(buf, pos^, order))));     size = 4
	case DW_EH_PE_SDATA8: value = elf.read_u64(buf, pos^, order);                    size = 8
	case:                 return 0, fmt.tprintf("unsupported pointer format 0x%x", format)
	}

	if pos^ + size > len(buf) {
		return 0, "truncated .eh_frame_hdr"
	}
	pos^ += size
	return base + value, ""
}
