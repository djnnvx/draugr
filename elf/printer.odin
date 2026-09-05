package elf

import "core:fmt"
import "core:os"

print_info :: proc(info: ^ELF_Info, verbose: bool) {
	f := os.stdout

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

	if info.soname != "" {
		fmt.fprintf(f, "SONAME:    %s\n", info.soname)
	}
	if info.rpath != "" {
		fmt.fprintf(f, "RPATH:     %s\n", info.rpath)
	}
	if info.runpath != "" {
		fmt.fprintf(f, "RUNPATH:   %s\n", info.runpath)
	}
	if len(info.needed) > 0 {
		fmt.fprintf(f, "\nNeeded Libraries: %d\n", len(info.needed))
		for lib in info.needed {
			fmt.fprintf(f, "  %s\n", lib)
		}
	}

	fmt.fprintf(f, "\n")
	fmt.fprintf(f, "Program Headers: %d\n", len(info.program_hdrs))
	fmt.fprintf(f, "Section Headers: %d\n", len(info.section_hdrs))
	fmt.fprintf(f, "Symbols (static): %d\n", len(info.symbols))
	fmt.fprintf(f, "Symbols (dynamic): %d\n", len(info.dyn_symbols))

	if verbose {
		if len(info.dyn_entries) > 0 {
			fmt.fprintf(f, "\nDynamic Section: %d entries\n", len(info.dyn_entries))
			for e in info.dyn_entries {
				if name := dyn_string(info, e); name != "" {
					fmt.fprintf(f, "  %-14s %s\n", dyn_tag_str(e.tag), name)
				} else {
					fmt.fprintf(f, "  %-14s 0x%x\n", dyn_tag_str(e.tag), e.val)
				}
			}
		}

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
	case EM_SPARC:        return "SPARC"
	case EM_386:          return "x86 (i386)"
	case EM_68K:          return "m68k"
	case EM_MIPS:         return "MIPS"
	case EM_MIPS_RS3_LE:  return "MIPS RS3 LE"
	case EM_PARISC:       return "PA-RISC"
	case EM_PPC:          return "PowerPC"
	case EM_PPC64:        return "PowerPC64"
	case EM_S390:         return "S/390"
	case EM_ARM:          return "ARM"
	case EM_SH:           return "SuperH"
	case EM_SPARCV9:      return "SPARC V9"
	case EM_ARC:          return "ARC"
	case EM_IA_64:        return "IA-64"
	case EM_X86_64:       return "x86-64"
	case EM_CRIS:         return "CRIS"
	case EM_AVR:          return "AVR"
	case EM_FR30:         return "FR30"
	case EM_V850:         return "V850"
	case EM_M32R:         return "M32R"
	case EM_OPENRISC:     return "OpenRISC"
	case EM_ARC_COMPACT:  return "ARCompact"
	case EM_XTENSA:       return "Xtensa"
	case EM_MSP430:       return "MSP430"
	case EM_BLACKFIN:     return "Blackfin"
	case EM_UNICORE:      return "UniCore"
	case EM_TI_C6000:     return "TI C6000"
	case EM_NDS32:        return "NDS32"
	case EM_AARCH64:      return "AArch64"
	case EM_MICROBLAZE:   return "MicroBlaze"
	case EM_TILEGX:       return "TILE-Gx"
	case EM_ARC_COMPACT2: return "ARCv2"
	case EM_RISCV:        return "RISC-V"
	case EM_BPF:          return "BPF"
	case EM_CSKY:         return "C-SKY"
	case EM_LOONGARCH:    return "LoongArch"
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
	case PT_GNU_PROPERTY: return "GNU_PROPERTY"
	}
	return fmt.tprintf("0x%x", t)
}

// bit 0 = X, bit 1 = W, bit 2 = R
flags_to_str :: proc(flags: u64) -> string {
	@static table := [8]string{"   ", "  X", " W ", " WX", "R  ", "R X", "RW ", "RWX"}
	return table[flags & 7]
}

print_checksec :: proc(info: ^ELF_Info) {
	f := os.stdout
	c := checksec(info)

	fmt.fprintf(f, "%-12s %s\n", "RELRO:", relro_str(c.relro))
	fmt.fprintf(f, "%-12s %s\n", "Stack:", "Canary found" if c.canary else "No canary found")
	fmt.fprintf(f, "%-12s %s\n", "NX:", nx_str(c.nx))
	fmt.fprintf(f, "%-12s %s\n", "PIE:", pie_str(c.pie))
	fmt.fprintf(f, "%-12s %s\n", "RPATH:", c.rpath if c.rpath != "" else "No RPATH")
	fmt.fprintf(f, "%-12s %s\n", "RUNPATH:", c.runpath if c.runpath != "" else "No RUNPATH")
	fmt.fprintf(f, "%-12s %s\n", "Symbols:", "No symbols" if c.stripped else "Symbols")
	fmt.fprintf(f, "%-12s %d of %d fortifiable functions fortified", "FORTIFY:", c.fortified, c.fortifiable)
	if c.partial > 0 {
		fmt.fprintf(f, " (%d also imported unfortified)", c.partial)
	}
	fmt.fprintf(f, "\n")

	if c.textrel {
		fmt.fprintf(f, "%-12s DT_TEXTREL present, code segment is writable at load time\n", "TEXTREL:")
	}
	if c.rwx_segment {
		fmt.fprintf(f, "%-12s a PT_LOAD segment is both writable and executable\n", "RWX:")
	}
}

print_relocs :: proc(info: ^ELF_Info) {
	f := os.stdout

	if len(info.relocs) == 0 {
		fmt.fprintf(f, "No relocations\n")
		return
	}

	fmt.fprintf(f, "%-18s %-22s %-16s %s\n", "Offset", "Type", "Addend", "Symbol")
	for r in info.relocs {
		addend := fmt.tprintf("0x%x", r.addend) if r.kind == .Rela else "-"
		fmt.fprintf(f, "0x%016x %-22s %-16s %s\n",
			r.offset, reloc_type_str(info.header.machine, r.type), addend, r.sym_name)
	}

	fmt.fprintf(f, "\nPLT/GOT Map:\n")
	slots := 0
	for r in info.relocs {
		if !is_jump_slot(info.header.machine, r.type) || r.sym_name == "" {
			continue
		}
		slots += 1
		fmt.fprintf(f, "  %-32s 0x%016x\n", r.sym_name, r.offset)
	}
	if slots == 0 {
		fmt.fprintf(f, "  (no jump slots)\n")
	}
}
