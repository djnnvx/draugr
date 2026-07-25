// main.odin - draugr: ELF mapping and analysis tool
package main

import "core:flags"
import "core:fmt"
import "core:os"

import "./elf"
import "./analysis"

// Author: djnn

Options :: struct {
	elf_path    : string `args:"pos=0,required" usage:"ELF binary to analyse."`,
	hexdump     : bool   `usage:"Hex dump entire file to stdout."`,
	hexdump_out : string `usage:"Hex dump to file."`,
	disasm      : bool   `usage:"Disassemble code sections."`,
	disasm_out  : string `usage:"Disassemble to file."`,
	entropy     : bool   `usage:"Shannon entropy report."`,
	entropy_out : string `usage:"Entropy report to file."`,
	symbols     : bool   `usage:"Print symbol table (nm-like)."`,
	sections    : bool   `usage:"Print section headers."`,
	segments    : bool   `usage:"Print program headers (objdump -p style)."`,
	show_map    : bool   `args:"name=map" usage:"Visual memory layout map."`,
	remap       : string `usage:"Remap using this prototype file."`,
	info        : bool   `usage:"Print ELF summary only."`,
	json        : bool   `usage:"Output in JSON format."`,
	verbose     : bool   `usage:"Verbose output."`,
}

main :: proc() {
	opts: Options
	flags.parse_or_exit(&opts, os.args, .Unix)

	elf_data, read_err := os.read_entire_file_from_path(opts.elf_path, context.allocator)
	if read_err != nil {
		fmt.fprintf(os.stderr, "Failed to read file: %s\n", opts.elf_path)
		os.exit(1)
	}

	if !elf.probe(elf_data) {
		fmt.fprintf(os.stderr, "Not a valid ELF file: %s\n", opts.elf_path)
		os.exit(1)
	}

	info, parse_err := elf.load(elf_data)
	if parse_err != "" {
		fmt.fprintf(os.stderr, "ELF parse error: %s\n", parse_err)
		os.exit(1)
	}
	defer elf.destroy(&info)

	bits := 64 if info.is_64bit else 32
	elf_type := "PIE" if info.is_pie else "ET_EXEC"
	dyn_type := "dynamic" if info.is_dynamic else "static"

	fmt.fprintln(os.stderr, "----------------------------------------")
	fmt.fprintf(os.stderr, "arch=%-12s class=ELF%d\t%s\t%s\n",
		elf.machine_to_str(info.header.machine), bits, elf_type, dyn_type)
	fmt.fprintln(os.stderr, "")

	if opts.info {
		elf.print_info(&info, opts.verbose, opts.json)
		return
	}

	failed := false

	if opts.hexdump || opts.hexdump_out != "" {
		section_header("Hexdump", opts.hexdump_out)
		report("Hexdump", analysis.hexdump(elf_data, 0, opts.hexdump_out), &failed)
		fmt.println("")
	}

	if opts.entropy || opts.entropy_out != "" {
		section_header("Entropy Analysis", opts.entropy_out)
		report("Entropy", analysis.entropy_output(elf_data, opts.entropy_out), &failed)
		fmt.println("")
	}

	if opts.disasm || opts.disasm_out != "" {
		section_header("Disassembly", opts.disasm_out)
		report("Disasm", analysis.disasm_output(elf_data, &info, opts.disasm_out), &failed)
		fmt.println("")
	}

	if opts.symbols {
		section_header("Symbol Table (nm-style)", "")
		print_symbols(&info)
		fmt.println("")
	}

	if opts.sections {
		section_header("Section Headers", "")
		print_sections(&info)
		fmt.println("")
	}

	if opts.segments {
		section_header("Program Headers (objdump-style)", "")
		print_segments(&info)
		fmt.println("")
	}

	if opts.show_map {
		section_header("Memory Map", "")
		report("Map", analysis.map_output(elf_data, &info, ""), &failed)
		fmt.println("")
	}

	if opts.remap != "" {
		section_header("Remap", "")
		report("Remap", analysis.remap_output(elf_data, &info, opts.remap, ""), &failed)
		fmt.println("")
	}

	if failed {
		os.exit(1)
	}
}

report :: proc(label: string, err: string, failed: ^bool) {
	if err == "" {
		return
	}
	fmt.fprintf(os.stderr, "%s error: %s\n", label, err)
	failed^ = true
}

section_header :: proc(title: string, out_path: string) {
	fmt.fprintln(os.stderr, "----------------------------------------")
	if out_path == "" {
		fmt.fprintf(os.stderr, "%s:\n", title)
	} else {
		fmt.fprintf(os.stderr, "%s -> %s\n", title, out_path)
	}
}


print_symbols :: proc(info: ^elf.ELF_Info) {
	print_symbol_table(info.symbols[:])
	print_symbol_table(info.dyn_symbols[:])
}

print_symbol_table :: proc(syms: []elf.Symbol) {
	for sym in syms {
		if sym.name == "" {
			continue
		}
		if sym.shndx == elf.SHN_UNDEF {
			fmt.printf("%18s %c %s\n", "", sym_to_nm_type(sym), sym.name)
		} else {
			fmt.printf("0x%016x %c %s\n", sym.value, sym_to_nm_type(sym), sym.name)
		}
	}
}

// Odin's fmt zero-fills numeric widths, so decimal columns pad via a string.
print_sections :: proc(info: ^elf.ELF_Info) {
	fmt.printf("%-4s %-20s %-10s %-10s %-10s %s\n",
		"Idx", "Name", "Type", "Addr", "Offset", "Size")

	for shdr, i in info.section_hdrs {
		name := elf.get_section_name(info, shdr)
		if name == "" {
			name = fmt.tprintf("[%d]", i)
		}
		fmt.printf("%-4s %-20s %-10s 0x%08x 0x%08x 0x%x\n",
			fmt.tprintf("%d", i), name, elf.section_type_str(shdr.type),
			shdr.addr, shdr.offset, shdr.size)
	}
}

print_segments :: proc(info: ^elf.ELF_Info) {
	fmt.printf("%-13s %-5s %-10s %-10s %-10s %s\n",
		"Type", "Flags", "Offset", "VirtAddr", "FileSize", "MemSize")

	for ph in info.program_hdrs {
		fmt.printf("%-13s %-5s 0x%08x 0x%08x 0x%08x 0x%08x\n",
			elf.segment_type_str(ph.type),
			elf.flags_to_str(ph.flags),
			ph.offset, ph.vaddr, ph.filesz, ph.memsz)
	}
}

sym_to_nm_type :: proc(sym: elf.Symbol) -> u8 {
	if sym.shndx == elf.SHN_UNDEF {
		return 'U'
	}

	letter: u8 = '?'
	switch sym.type {
	case elf.STT_NOTYPE:  letter = ' '
	case elf.STT_OBJECT:  letter = 'O'
	case elf.STT_FUNC:    letter = 'T'
	case elf.STT_SECTION: letter = 'S'
	case elf.STT_FILE:    letter = 'F'
	}

	if sym.bind == elf.STB_LOCAL && letter >= 'A' && letter <= 'Z' {
		letter += 'a' - 'A'
	}
	return letter
}
