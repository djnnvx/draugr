package analysis

import "core:fmt"
import "core:os"
import "core:slice"
import "core:strings"

import "../elf"

Section_Delta :: struct {
	name  : string,
	a     : u64,
	b     : u64,
	delta : i64,
}

bin_diff_output :: proc(data: []u8, info: ^elf.ELF_Info, ref_path: string, out_path: string) -> string {
	ref_data, read_err := os.read_entire_file_from_path(ref_path, context.allocator)
	if read_err != nil {
		return fmt.tprintf("failed to read reference file: %s", ref_path)
	}
	defer delete(ref_data)

	if !elf.probe(ref_data) {
		return fmt.tprintf("reference is not an ELF file: %s", ref_path)
	}

	ref, parse_err := elf.load(ref_data)
	if parse_err != "" {
		return fmt.tprintf("reference parse error: %s", parse_err)
	}
	defer elf.destroy(&ref)

	f, err := open_out(out_path)
	if err != "" {
		return err
	}
	defer close_out(f, out_path)

	fmt.fprintf(f, "Binary Diff\n")
	fmt.fprintf(f, "===========\n\n")
	fmt.fprintf(f, "reference: %s\n\n", ref_path)

	diff_header(f, info, &ref, len(data), len(ref_data))
	diff_segments(f, info, &ref)
	diff_sections(f, info, &ref)
	diff_needed(f, info, &ref)

	return ""
}

diff_header :: proc(f: ^os.File, a: ^elf.ELF_Info, b: ^elf.ELF_Info, a_size: int, b_size: int) {
	fmt.fprintf(f, "Header:\n")
	row_str(f, "class", "ELF64" if a.is_64bit else "ELF32", "ELF64" if b.is_64bit else "ELF32")
	row_str(f, "machine", elf.machine_to_str(a.header.machine), elf.machine_to_str(b.header.machine))
	row_str(f, "type", elf.type_to_str(a.header.type), elf.type_to_str(b.header.type))
	row_hex(f, "entry", a.header.entry, b.header.entry)
	row_num(f, "file size", i64(a_size), i64(b_size))
	fmt.fprintf(f, "\n")
}

diff_segments :: proc(f: ^os.File, a: ^elf.ELF_Info, b: ^elf.ELF_Info) {
	fmt.fprintf(f, "Segments:\n")
	row_num(f, "count", i64(len(a.program_hdrs)), i64(len(b.program_hdrs)))

	n := min(len(a.program_hdrs), len(b.program_hdrs))
	for i := 0; i < n; i += 1 {
		pa, pb := a.program_hdrs[i], b.program_hdrs[i]
		if pa.type == pb.type && pa.vaddr == pb.vaddr && pa.filesz == pb.filesz &&
		   pa.memsz == pb.memsz && pa.flags == pb.flags {
			continue
		}
		label := elf.segment_type_str(pa.type)
		if pa.type != pb.type {
			label = fmt.tprintf("%s -> %s", label, elf.segment_type_str(pb.type))
		}
		fmt.fprintf(f, "  ~ [%d] %s%s%s%s\n", i, label,
			delta_hex("vaddr", pa.vaddr, pb.vaddr),
			delta_hex("filesz", pa.filesz, pb.filesz),
			delta_hex("memsz", pa.memsz, pb.memsz))
	}
	fmt.fprintf(f, "\n")
}

diff_sections :: proc(f: ^os.File, a: ^elf.ELF_Info, b: ^elf.ELF_Info) {
	a_sizes := section_sizes(a)
	defer delete(a_sizes)
	b_sizes := section_sizes(b)
	defer delete(b_sizes)

	fmt.fprintf(f, "Sections:\n")

	changed := make([dynamic]Section_Delta)
	defer delete(changed)

	for name, a_size in a_sizes {
		b_size, in_b := b_sizes[name]
		if !in_b {
			fmt.fprintf(f, "  - %-24s 0x%x (removed)\n", name, a_size)
			continue
		}
		if a_size != b_size {
			append(&changed, Section_Delta{name, a_size, b_size, i64(b_size) - i64(a_size)})
		}
	}
	for name, b_size in b_sizes {
		if _, in_a := a_sizes[name]; !in_a {
			fmt.fprintf(f, "  + %-24s 0x%x (added)\n", name, b_size)
		}
	}

	slice.sort_by(changed[:], proc(x, y: Section_Delta) -> bool {
		return abs_i64(x.delta) > abs_i64(y.delta)
	})
	for c in changed {
		fmt.fprintf(f, "  ~ %-24s 0x%x -> 0x%x (%+d)\n", c.name, c.a, c.b, c.delta)
	}

	if len(changed) == 0 && len(a_sizes) == len(b_sizes) {
		fmt.fprintf(f, "  no size changes\n")
	}
	fmt.fprintf(f, "\n")
}

section_sizes :: proc(info: ^elf.ELF_Info) -> map[string]u64 {
	out := make(map[string]u64)
	for shdr in info.section_hdrs {
		name := elf.get_section_name(info, shdr)
		if name == "" || shdr.type == elf.SHT_NULL {
			continue
		}
		out[name] = shdr.size
	}
	return out
}

diff_needed :: proc(f: ^os.File, a: ^elf.ELF_Info, b: ^elf.ELF_Info) {
	fmt.fprintf(f, "Dependencies:\n")
	changed := false
	for lib in a.needed {
		if !slice.contains(b.needed[:], lib) {
			fmt.fprintf(f, "  - %s\n", lib)
			changed = true
		}
	}
	for lib in b.needed {
		if !slice.contains(a.needed[:], lib) {
			fmt.fprintf(f, "  + %s\n", lib)
			changed = true
		}
	}
	if a.runpath != b.runpath {
		row_str(f, "runpath", a.runpath, b.runpath)
		changed = true
	}
	if a.rpath != b.rpath {
		row_str(f, "rpath", a.rpath, b.rpath)
		changed = true
	}
	if !changed {
		fmt.fprintf(f, "  unchanged\n")
	}
	fmt.fprintf(f, "\n")
}

delta_hex :: proc(label: string, a: u64, b: u64) -> string {
	if a == b {
		return ""
	}
	return fmt.tprintf("  %s 0x%x -> 0x%x", label, a, b)
}

abs_i64 :: proc(v: i64) -> i64 {
	return -v if v < 0 else v
}

row_str :: proc(f: ^os.File, label: string, a: string, b: string) {
	mark := " " if a == b else "~"
	if a == b {
		fmt.fprintf(f, "  %s %-12s %s\n", mark, label, a)
	} else {
		fmt.fprintf(f, "  %s %-12s %s -> %s\n", mark, label, a, b)
	}
}

row_hex :: proc(f: ^os.File, label: string, a: u64, b: u64) {
	if a == b {
		fmt.fprintf(f, "    %-12s 0x%x\n", label, a)
	} else {
		fmt.fprintf(f, "  ~ %-12s 0x%x -> 0x%x\n", label, a, b)
	}
}

row_num :: proc(f: ^os.File, label: string, a: i64, b: i64) {
	if a == b {
		fmt.fprintf(f, "    %-12s %d\n", label, a)
	} else {
		fmt.fprintf(f, "  ~ %-12s %d -> %d (%+d)\n", label, a, b, b - a)
	}
}
