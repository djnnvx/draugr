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
	code        : bool   `usage:"Code region report: executable sections, entry point, function starts."`,
	code_out    : string `usage:"Code region report to file."`,
	entropy     : bool   `usage:"Shannon entropy report."`,
	entropy_out : string `usage:"Entropy report to file."`,
	symbols     : bool   `usage:"Print symbol table (nm-like)."`,
	sections    : bool   `usage:"Print section headers."`,
	segments    : bool   `usage:"Print program headers (objdump -p style)."`,
	show_map    : bool   `args:"name=map" usage:"Visual memory layout map."`,
	bin_diff    : string `args:"name=bin-diff" usage:"Diff this binary's layout against a reference ELF."`,
	call_func   : string `args:"name=call-function" usage:"Load from memory and call this symbol."`,
	call_args   : string `args:"name=call-args" usage:"Comma-separated args for --call-function: integers, or s:string."`,
	patch       : string `args:"name=patch" usage:"Semicolon-separated in-memory patches applied before --call-function. Specs: sym=ret:N, sym=jmp:target, got:sym=target."`,
	checksec    : bool   `usage:"Hardening report: RELRO, NX, canary, PIE, RPATH, FORTIFY."`,
	relocs      : bool   `usage:"Relocation table and PLT/GOT map."`,
	info        : bool   `usage:"Print ELF summary only."`,
	json        : bool   `usage:"Full structured dump as JSON (header, segments, sections, dynamic, symbols, relocations, GOT, checksec)."`,
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

	if opts.patch != "" && opts.call_func == "" {
		fmt.fprintln(os.stderr, "--patch requires --call-function")
		os.exit(1)
	}

	if opts.json {
		if opts.hexdump || opts.hexdump_out != "" ||
		   opts.entropy || opts.entropy_out != "" ||
		   opts.code    || opts.code_out    != "" ||
		   opts.show_map || opts.bin_diff != "" || opts.call_func != "" {
			fmt.fprintln(os.stderr, "--json is not supported with --hexdump, --entropy, --code, --map, --bin-diff or --call-function")
			os.exit(1)
		}
		if err := elf.print_json(&info); err != "" {
			fmt.fprintln(os.stderr, err)
			os.exit(1)
		}
		return
	}

	if opts.info {
		elf.print_info(&info, opts.verbose)
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

	if opts.code || opts.code_out != "" {
		section_header("Code Regions", opts.code_out)
		report("Code", analysis.code_output(elf_data, &info, opts.code_out), &failed)
		fmt.println("")
	}

	if opts.checksec {
		section_header("Checksec", "")
		elf.print_checksec(&info)
		fmt.println("")
	}

	if opts.relocs {
		section_header("Relocations", "")
		elf.print_relocs(&info)
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

	if opts.call_func != "" {
		section_header("Call Function", "")
		report("Call", analysis.call_function(elf_data, &info, opts.elf_path, opts.call_func, opts.call_args, opts.patch), &failed)
		fmt.println("")
	}

	if opts.bin_diff != "" {
		section_header("Binary Diff", "")
		report("BinDiff", analysis.bin_diff_output(elf_data, &info, opts.bin_diff, ""), &failed)
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
