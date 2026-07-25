// analysis/mapper.odin - ELF memory mapping visualization
package analysis

import "core:fmt"
import "core:os"

import "../elf"

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

map_output :: proc(data: []u8, info: ^elf.ELF_Info, out_path: string) -> string {
	f, err := open_out(out_path)
	if err != "" {
		return err
	}
	defer close_out(f, out_path)

	fmt.fprintf(f, "ELF Memory Map\n")
	fmt.fprintf(f, "==============\n\n")

	fmt.fprintf(f, "File Layout:\n")
	fmt.fprintf(f, "%s\n", "------------------------------------------")
	fmt.fprintf(f, "0x%08x: ELF Header (64 bytes)\n", 0)

	if info.header.phoff > 0 {
		ph_end := info.header.phoff + u64(len(info.program_hdrs)) * u64(info.header.phentsize)
		fmt.fprintf(f, "0x%08x: Program Headers\n", info.header.phoff)
		fmt.fprintf(f, "0x%08x: Program Headers End\n", ph_end)
	}

	if info.header.shoff > 0 {
		sh_end := info.header.shoff + u64(len(info.section_hdrs)) * u64(info.header.shentsize)
		fmt.fprintf(f, "0x%08x: Section Headers\n", info.header.shoff)
		fmt.fprintf(f, "0x%08x: Section Headers End\n", sh_end)
	}

	fmt.fprintf(f, "0x%08x: EOF (file size: %d bytes)\n\n", len(data), len(data))

	fmt.fprintf(f, "Segments:\n")
	fmt.fprintf(f, "%-13s %-10s %-10s %-10s %-10s %s\n", "Type", "Offset", "VirtAddr", "FileSize", "MemSize", "Flags")
	fmt.fprintf(f, "%s\n", "---------------------------------------------------------------------")

	for i := 0; i < len(info.program_hdrs); i += 1 {
		ph := info.program_hdrs[i]
		type_str := elf.segment_type_str(ph.type)
		flags_str := elf.flags_to_str(ph.flags)

		fmt.fprintf(f, "%-13s 0x%08x 0x%08x 0x%08x 0x%08x %s\n",
			type_str, ph.offset, ph.vaddr, ph.filesz, ph.memsz, flags_str)

		if ph.filesz > 0 {
			if ph.type != elf.PT_NULL {
				print_bar(f, ph.offset, ph.filesz, len(data))
			}
		}
	}

	fmt.fprintf(f, "\n")

	fmt.fprintf(f, "Sections:\n")
	fmt.fprintf(f, "%-16s %-10s %-10s %-10s %s\n", "Name", "Type", "Addr", "Offset", "Size")
	fmt.fprintf(f, "%s\n", "------------------------------------------------------------")

	for i := 0; i < len(info.section_hdrs); i += 1 {
		shdr := info.section_hdrs[i]
		name := elf.get_section_name(info, shdr)
		if name == "" {
			name = fmt.tprintf("[%d]", i)
		}

		type_str := elf.section_type_str(shdr.type)

		fmt.fprintf(f, "%-16s %-10s 0x%08x 0x%08x 0x%x\n",
			name, type_str, shdr.addr, shdr.offset, shdr.size)
	}

	return ""
}

remap_output :: proc(data: []u8, info: ^elf.ELF_Info, proto_path: string, out_path: string) -> string {
	f, err := open_out(out_path)
	if err != "" {
		return err
	}
	defer close_out(f, out_path)

	fmt.fprintf(f, "ELF Remapping (stub - prototype: %s)\n", proto_path)
	return ""
}

//------------------------------------------------------------------------------
// Internal Helpers
//------------------------------------------------------------------------------

print_bar :: proc(f: ^os.File, offset: u64, size: u64, total: int) {
	if total <= 0 {
		return
	}
	bar_width := 50
	start := int(offset * u64(bar_width) / u64(total))
	end := int((offset + size) * u64(bar_width) / u64(total))
	if end > bar_width {
		end = bar_width
	}

	fmt.fprintf(f, "  [|")
	for i := 0; i < bar_width; i += 1 {
		if i >= start {
			if i < end {
				fmt.fprintf(f, "#")
			} else {
				fmt.fprintf(f, "-")
			}
		} else {
			fmt.fprintf(f, "-")
		}
	}
	fmt.fprintf(f, "|]\n")
}

