// analysis/disasm.odin - Disassembly (stub/simple)
package analysis

import "core:fmt"
import "core:os"

import "../elf"

disasm_output :: proc(data: []u8, info: ^elf.ELF_Info, out_path: string) -> string {
	f, err := open_out(out_path)
	if err != "" {
		return err
	}
	defer close_out(f, out_path)

	fmt.fprintf(f, "Disassembly Analysis\n")
	fmt.fprintf(f, "====================\n\n")

	fmt.fprintf(f, "Executable Sections:\n")
	fmt.fprintf(f, "%-20s %-12s %-12s %s\n", "Name", "Offset", "Size", "VAddr")
	fmt.fprintf(f, "%s\n", "-------------------------------------------------")

	for i := 0; i < len(info.section_hdrs); i += 1 {
		shdr := info.section_hdrs[i]
		if shdr.type == elf.SHT_NULL {
			continue
		}

		name := elf.get_section_name(info, shdr)

		if shdr.flags & elf.SHF_EXECINSTR != 0 {
			fmt.fprintf(f, "%-20s 0x%08x 0x%08x 0x%016x\n", 
				name, shdr.offset, shdr.size, shdr.addr)

		if int(shdr.offset) < len(data) {
			end := int(shdr.offset + shdr.size)
			if end > len(data) {
				end = len(data)
			}
				section_data := data[int(shdr.offset):end]

				fmt.fprintf(f, "  First 64 bytes (hex): ")
				for j := 0; j < len(section_data); j += 1 {
					if j >= 64 {
						break
					}
					fmt.fprintf(f, "%02x ", section_data[j])
				}
				fmt.fprintf(f, "\n")
			}
		}
	}

	fmt.fprintf(f, "\nNote: Full disassembly requires external disassembler\n")
	fmt.fprintf(f, "Consider integrating zydis or capstone for x86/x64\n")

	return ""
}