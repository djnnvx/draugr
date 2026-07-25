// elf/printer.odin - ELF info printing
package elf

import "core:fmt"
import "core:os"

print_info :: proc(info: ^ELF_Info, verbose: bool, json: bool) {
	f := os.stdout

	if json {
		print_info_json(info)
		return
	}

	fmt.fprintf(f, "ELF File Information\n")
	fmt.fprintf(f, "====================\n\n")

	class_bits := 32
	if info.is_64bit {
		class_bits = 64
	}
	fmt.fprintf(f, "Class:     ELF%d\n", class_bits)
	fmt.fprintf(f, "Type:      %s\n", type_to_str(info.header.type))
	fmt.fprintf(f, "Machine:   %s\n", machine_to_str(info.header.machine))
	fmt.fprintf(f, "Entry:     0x%016x\n", info.header.entry)
	fmt.fprintf(f, "Flags:     0x%08x\n", info.header.flags)

	pie_str := "no"
	if info.is_pie {
		pie_str = "yes"
	}
	dyn_str := "no"
	if info.is_dynamic {
		dyn_str = "yes"
	}
	fmt.fprintf(f, "PIE:       %s\n", pie_str)
	fmt.fprintf(f, "Dynamic:   %s\n", dyn_str)
	if info.interp_offset != 0 {
		fmt.fprintf(f, "Interpreter offset: 0x%x\n", info.interp_offset)
	}

	fmt.fprintf(f, "\n")
	fmt.fprintf(f, "Program Headers: %d\n", len(info.program_hdrs))
	fmt.fprintf(f, "Section Headers: %d\n", len(info.section_hdrs))
	fmt.fprintf(f, "Symbols (static): %d\n", len(info.symbols))
	fmt.fprintf(f, "Symbols (dynamic): %d\n", len(info.dyn_symbols))

	if verbose {
		fmt.fprintf(f, "\n")
		fmt.fprintf(f, "Detailed Sections:\n")
		for i := 0; i < len(info.section_hdrs); i += 1 {
			shdr := info.section_hdrs[i]
			name := get_section_name(info, shdr)
			if name == "" {
				name = fmt.tprintf("[%d]", i)
			}
			fmt.fprintf(f, "  [%2d] %-20s %-12s 0x%08x 0x%06x 0x%x\n",
				i, name, section_type_str(shdr.type), shdr.addr, shdr.offset, shdr.size)
		}

		if len(info.symbols) > 0 {
			fmt.fprintf(f, "\nStatic Symbols (first 20):\n")
			count := 20
			if len(info.symbols) < count {
				count = len(info.symbols)
			}
			for i := 0; i < count; i += 1 {
				sym := info.symbols[i]
				sym_type := symbol_type_str(sym.type)
				sym_bind := symbol_bind_str(sym.bind)
				fmt.fprintf(f, "  %-30s %s %-8s 0x%016x (size: %d)\n",
					sym.name, sym_bind, sym_type, sym.value, sym.size)
			}
		}

		if len(info.dyn_symbols) > 0 {
			fmt.fprintf(f, "\nDynamic Symbols (first 20):\n")
			count := 20
			if len(info.dyn_symbols) < count {
				count = len(info.dyn_symbols)
			}
			for i := 0; i < count; i += 1 {
				sym := info.dyn_symbols[i]
				sym_type := symbol_type_str(sym.type)
				sym_bind := symbol_bind_str(sym.bind)
				fmt.fprintf(f, "  %-30s %s %-8s 0x%016x (size: %d)\n",
					sym.name, sym_bind, sym_type, sym.value, sym.size)
			}
		}
	}
}

print_info_json :: proc(info: ^ELF_Info) {
	class_bits := 32
	if info.is_64bit {
		class_bits = 64
	}
	fmt.println("{")
	fmt.printf("  \"class\": %d,\n", class_bits)
	fmt.printf("  \"type\": \"%s\",\n", type_to_str(info.header.type))
	fmt.printf("  \"machine\": \"%s\",\n", machine_to_str(info.header.machine))
	fmt.printf("  \"entry\": \"0x%016x\",\n", info.header.entry)
	pie_str := "false"
	if info.is_pie {
		pie_str = "true"
	}
	fmt.printf("  \"pie\": %s,\n", pie_str)
	dyn_str := "false"
	if info.is_dynamic {
		dyn_str = "true"
	}
	fmt.printf("  \"dynamic\": %s,\n", dyn_str)
	fmt.printf("  \"program_headers\": %d,\n", len(info.program_hdrs))
	fmt.printf("  \"section_headers\": %d,\n", len(info.section_hdrs))
	fmt.printf("  \"symbols_static\": %d,\n", len(info.symbols))
	fmt.printf("  \"symbols_dynamic\": %d\n", len(info.dyn_symbols))
	fmt.printf("}\n")
}

type_to_str :: proc(t: u16) -> string {
	switch t {
	case ET_REL:  return "REL (Relocatable)"
	case ET_EXEC: return "EXEC (Executable)"
	case ET_DYN:  return "DYN (Shared Object/PIE)"
	case ET_CORE: return "CORE"
	}
	return fmt.tprintf("UNKNOWN (%d)", t)
}

machine_to_str :: proc(m: u16) -> string {
	switch m {
	case EM_386:     return "x86 (i386)"
	case EM_MIPS:    return "MIPS"
	case EM_PPC:     return "PowerPC"
	case EM_PPC64:   return "PowerPC64"
	case EM_ARM:     return "ARM"
	case EM_X86_64:  return "x86-64"
	case EM_AARCH64: return "AArch64"
	case EM_RISCV:   return "RISC-V"
	}
	return fmt.tprintf("Unknown (%d)", m)
}

section_type_str :: proc(t: u32) -> string {
	switch t {
	case SHT_NULL:     return "NULL"
	case SHT_PROGBITS: return "PROGBITS"
	case SHT_SYMTAB:   return "SYMTAB"
	case SHT_STRTAB:   return "STRTAB"
	case SHT_RELA:     return "RELA"
	case SHT_HASH:     return "HASH"
	case SHT_DYNAMIC:  return "DYNAMIC"
	case SHT_NOTE:     return "NOTE"
	case SHT_NOBITS:   return "NOBITS"
	case SHT_REL:      return "REL"
	case SHT_DYNSYM:   return "DYNSYM"
	case SHT_SHLIB:          return "SHLIB"
	case SHT_INIT_ARRAY:     return "INIT_ARRAY"
	case SHT_FINI_ARRAY:     return "FINI_ARRAY"
	case SHT_PREINIT_ARRAY:  return "PREINIT_ARRAY"
	case SHT_GROUP:          return "GROUP"
	case SHT_SYMTAB_SHNDX:   return "SYMTAB SECTION INDICES"
	case SHT_GNU_ATTRIBUTES: return "GNU_ATTRIBUTES"
	case SHT_GNU_HASH:       return "GNU_HASH"
	case SHT_GNU_VERDEF:     return "VERDEF"
	case SHT_GNU_VERNEED:    return "VERNEED"
	case SHT_GNU_VERSYM:     return "VERSYM"
	}
	return fmt.tprintf("0x%x", t)
}

symbol_type_str :: proc(t: u8) -> string {
	switch t {
	case STT_NOTYPE:  return "NOTYPE"
	case STT_OBJECT:  return "OBJECT"
	case STT_FUNC:    return "FUNC"
	case STT_SECTION: return "SECTION"
	case STT_FILE:    return "FILE"
	}
	return fmt.tprintf("0x%x", t)
}

symbol_bind_str :: proc(b: u8) -> string {
	switch b {
	case STB_LOCAL:  return "LOCAL"
	case STB_GLOBAL: return "GLOBAL"
	case STB_WEAK:   return "WEAK"
	}
	return fmt.tprintf("0x%x", b)
}

segment_type_str :: proc(t: u32) -> string {
	switch t {
	case PT_NULL:    return "NULL"
	case PT_LOAD:    return "LOAD"
	case PT_DYNAMIC: return "DYNAMIC"
	case PT_INTERP:  return "INTERP"
	case PT_NOTE:    return "NOTE"
	case PT_SHLIB:   return "SHLIB"
	case PT_PHDR:    return "PHDR"
	case PT_TLS:     return "TLS"
	case PT_GNU_EH_FRAME: return "GNU_EH_FRAME"
	case PT_GNU_STACK:    return "GNU_STACK"
	case PT_GNU_RELRO:    return "GNU_RELRO"
	}
	return fmt.tprintf("0x%x", t)
}

// bit 0 = X, bit 1 = W, bit 2 = R
flags_to_str :: proc(flags: u64) -> string {
	@static table := [8]string{"   ", "  X", " W ", " WX", "R  ", "R X", "RW ", "RWX"}
	return table[flags & 7]
}