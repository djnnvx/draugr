package analysis

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

import "../elf"

// Layout constants - built by doubling so the widths are provable, not counted

SP1  :: " "
SP2  :: SP1 + SP1
SP3  :: SP2 + SP1
SP4  :: SP2 + SP2
SP5  :: SP4 + SP1
SP6  :: SP4 + SP2
SP7  :: SP4 + SP3
SP8  :: SP4 + SP4
SP9  :: SP8 + SP1
SP10 :: SP8 + SP2
SP12 :: SP8 + SP4
SP13 :: SP8 + SP5
SP15 :: SP8 + SP7
SP16 :: SP8 + SP8
SP17 :: SP16 + SP1
SP32 :: SP16 + SP16
SP38 :: SP32 + SP6
SP47 :: SP32 + SP15

DASH1  :: "-"
DASH2  :: DASH1 + DASH1
DASH4  :: DASH2 + DASH2
DASH8  :: DASH4 + DASH4
DASH16 :: DASH8 + DASH8
DASH25 :: DASH16 + DASH8 + DASH1
DASH32 :: DASH16 + DASH16
DASH40 :: DASH32 + DASH8
DASH42 :: DASH40 + DASH2
DASH49 :: DASH32 + DASH16 + DASH1
DASH60 :: DASH32 + DASH16 + DASH8 + DASH4
DASH69 :: DASH60 + DASH8 + DASH1

HASH1  :: "#"
HASH2  :: HASH1 + HASH1
HASH4  :: HASH2 + HASH2
HASH8  :: HASH4 + HASH4
HASH16 :: HASH8 + HASH8
HASH25 :: HASH16 + HASH8 + HASH1
HASH50 :: HASH25 + HASH25

TOLERANCE :: 1e-9

tmp_path :: proc(name: string) -> string {
	dir, err := os.temp_directory(context.allocator)
	if err != nil {
		return fmt.aprintf("draugr_test_%s.out", name)
	}
	defer delete(dir)
	return fmt.aprintf("%s/draugr_test_%s.out", dir, name)
}

drop :: proc(path: string) {
	os.remove(path)
	delete(path)
}

read_all :: proc(t: ^testing.T, path: string) -> string {
	data, err := os.read_entire_file_from_path(path, context.allocator)
	testing.expectf(t, err == nil, "cannot read back %s: %v", path, err)
	return string(data)
}

expect_near :: proc(t: ^testing.T, got, want: f64, loc := #caller_location) {
	testing.expectf(t, abs(got - want) < TOLERANCE, "expected %.12f, got %.12f", want, got, loc = loc)
}

new_info :: proc() -> elf.ELF_Info {
	info: elf.ELF_Info
	info.program_hdrs = make([dynamic]elf.Program_Header)
	info.section_hdrs = make([dynamic]elf.Section_Header)
	info.symbols = make([dynamic]elf.Symbol)
	info.dyn_symbols = make([dynamic]elf.Symbol)
	return info
}

// offset 1 -> ".text", offset 7 -> ".data"
SHSTRTAB := [?]u8{0, '.', 't', 'e', 'x', 't', 0, '.', 'd', 'a', 't', 'a', 0}

@(test)
test_open_out_empty_path_returns_stdout :: proc(t: ^testing.T) {
	f, err := open_out("")

	testing.expect_value(t, err, "")
	testing.expect(t, f == os.stdout, "empty out_path must return os.stdout")
}

@(test)
test_close_out_leaves_stdout_open :: proc(t: ^testing.T) {
	f, err := open_out("")
	testing.expect_value(t, err, "")

	close_out(f, "")

	fi, ferr := os.fstat(os.stdout, context.allocator)
	testing.expectf(t, ferr == nil, "close_out closed stdout: %v", ferr)
	if ferr == nil {
		os.file_info_delete(fi, context.allocator)
	}
}

@(test)
test_open_out_unwritable_path_errors :: proc(t: ^testing.T) {
	f, err := open_out("/draugr_no_such_dir_4c1f/out.txt")

	testing.expect(t, f == nil, "failed open must return a nil handle")
	testing.expect(t, err != "", "failed open must return an error string")
	testing.expect(t, strings.contains(err, "cannot create"), "error must describe the failure")
}

@(test)
test_open_out_creates_file_and_close_out_persists_it :: proc(t: ^testing.T) {
	path := tmp_path("open_close")
	defer drop(path)

	f, err := open_out(path)
	testing.expect_value(t, err, "")
	testing.expect(t, f != nil, "real out_path must return a handle")
	testing.expect(t, f != os.stdout, "real out_path must not return stdout")

	fmt.fprintf(f, "draugr")
	close_out(f, path)

	testing.expect(t, os.exists(path), "close_out must leave the file on disk")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got, "draugr")
}

@(test)
test_hexdump_empty_data :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_empty")
	defer drop(path)

	testing.expect_value(t, hexdump([]u8{}, 0, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got, "")
}

@(test)
test_hexdump_full_line :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_full_line")
	defer drop(path)

	data := []u8{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	testing.expect_value(t, hexdump(data, 0, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		"00000000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  |................|\n")
}

@(test)
test_hexdump_printable_ascii_column :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_printable")
	defer drop(path)

	msg := "Hello, World!!!!"
	testing.expect_value(t, hexdump(transmute([]u8)msg, 0, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		"00000000  48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21 21 21 21  |Hello, World!!!!|\n")
}

@(test)
test_hexdump_short_trailing_line_is_padded :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_short")
	defer drop(path)

	data := []u8{'A', 'B', 'C', 'D'}
	testing.expect_value(t, hexdump(data, 0, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got, "00000000  41 42 43 44" + SP38 + "|ABCD" + SP12 + "|\n")
}

@(test)
test_hexdump_non_zero_offset :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_offset")
	defer drop(path)

	data := []u8{0xff}
	testing.expect_value(t, hexdump(data, 0x1000, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got, "00001000  ff" + SP47 + "|." + SP15 + "|\n")
}

@(test)
test_hexdump_offset_advances_per_line :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_multiline")
	defer drop(path)

	data := make([]u8, 20)
	defer delete(data)
	for i in 0 ..< 16 {
		data[i] = 'A'
	}
	for i in 16 ..< 20 {
		data[i] = 'B'
	}

	testing.expect_value(t, hexdump(data, 0x20, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		"00000020  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|\n" +
		"00000030  42 42 42 42" + SP38 + "|BBBB" + SP12 + "|\n")
}

@(test)
test_hexdump_non_printable_bytes_are_dots :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_nonprintable")
	defer drop(path)

	data := []u8{0x00, 0x0a, 0x1f, 0x7f, 0x80, 0xff}
	testing.expect_value(t, hexdump(data, 0, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got, "00000000  00 0a 1f 7f 80 ff" + SP32 + "|......" + SP10 + "|\n")
}

@(test)
test_hexdump_printable_boundaries_are_inclusive :: proc(t: ^testing.T) {
	path := tmp_path("hexdump_boundaries")
	defer drop(path)

	data := []u8{31, 32, 126, 127}
	testing.expect_value(t, hexdump(data, 0, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got, "00000000  1f 20 7e 7f" + SP38 + "|. ~." + SP12 + "|\n")
}

@(test)
test_calculate_entropy_empty_is_zero :: proc(t: ^testing.T) {
	expect_near(t, calculate_entropy([]u8{}), 0.0)
}

@(test)
test_calculate_entropy_single_value_is_zero :: proc(t: ^testing.T) {
	expect_near(t, calculate_entropy([]u8{0x41, 0x41, 0x41, 0x41, 0x41}), 0.0)
}

@(test)
test_calculate_entropy_two_values_is_one_bit :: proc(t: ^testing.T) {
	expect_near(t, calculate_entropy([]u8{0x00, 0xff}), 1.0)
	expect_near(t, calculate_entropy([]u8{0x00, 0x00, 0xff, 0xff}), 1.0)
}

@(test)
test_calculate_entropy_four_values_is_two_bits :: proc(t: ^testing.T) {
	data := []u8{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03}
	expect_near(t, calculate_entropy(data), 2.0)
}

// Pins the logarithm base: with the natural log this would be 5.545.
@(test)
test_calculate_entropy_all_256_values_is_eight_bits :: proc(t: ^testing.T) {
	data := make([]u8, 256)
	defer delete(data)
	for i in 0 ..< 256 {
		data[i] = u8(i)
	}

	expect_near(t, calculate_entropy(data), 8.0)
}

@(test)
test_calculate_entropy_lopsided_is_between_zero_and_one :: proc(t: ^testing.T) {
	data := []u8{0, 0, 0, 0, 0, 0, 0, 1}

	entropy := calculate_entropy(data)
	testing.expectf(t, entropy > 0.0, "7:1 split should be positive, got %.12f", entropy)
	testing.expectf(t, entropy < 1.0, "7:1 split should be under 1 bit, got %.12f", entropy)
	expect_near(t, entropy, 0.543564443)
}

ENTROPY_HEAD :: "Entropy Analysis (block size: 256 bytes)\n" +
                "Offset" + SP7 + "Size" + SP3 + "Entropy\n" +
                DASH40 + "\n"

@(test)
test_entropy_output_empty_data :: proc(t: ^testing.T) {
	path := tmp_path("entropy_empty")
	defer drop(path)

	testing.expect_value(t, entropy_output([]u8{}, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		ENTROPY_HEAD +
		"\nOverall entropy: 0.0000 bits/byte\n" +
		"Classification: Low entropy (text/code)\n")
}

@(test)
test_entropy_output_block_table_and_low_class :: proc(t: ^testing.T) {
	path := tmp_path("entropy_blocks")
	defer drop(path)

	data := make([]u8, 600)
	defer delete(data)

	testing.expect_value(t, entropy_output(data, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		ENTROPY_HEAD +
		"0x00000000" + SP3 + "256" + SP4 + "0.0000\n" +
		"0x00000100" + SP3 + "256" + SP4 + "0.0000\n" +
		"0x00000200" + SP3 + "88" + SP5 + "0.0000\n" +
		"\nOverall entropy: 0.0000 bits/byte\n" +
		"Classification: Low entropy (text/code)\n")
}

@(test)
test_entropy_output_medium_class :: proc(t: ^testing.T) {
	path := tmp_path("entropy_medium")
	defer drop(path)

	data := make([]u8, 32)
	defer delete(data)
	for i in 0 ..< 32 {
		data[i] = u8(i)
	}

	testing.expect_value(t, entropy_output(data, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		ENTROPY_HEAD +
		"0x00000000" + SP3 + "32" + SP5 + "5.0000\n" +
		"\nOverall entropy: 5.0000 bits/byte\n" +
		"Classification: Medium entropy (mixed)\n")
}

@(test)
test_entropy_output_high_class :: proc(t: ^testing.T) {
	path := tmp_path("entropy_high")
	defer drop(path)

	data := make([]u8, 256)
	defer delete(data)
	for i in 0 ..< 256 {
		data[i] = u8(i)
	}

	testing.expect_value(t, entropy_output(data, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		ENTROPY_HEAD +
		"0x00000000" + SP3 + "256" + SP4 + "8.0000\n" +
		"\nOverall entropy: 8.0000 bits/byte\n" +
		"Classification: High entropy (compressed/encrypted)\n")
}

// Brackets the 4.0 threshold from below without sitting on it.
@(test)
test_entropy_output_three_bits_is_low :: proc(t: ^testing.T) {
	path := tmp_path("entropy_three_bits")
	defer drop(path)

	data := make([]u8, 8)
	defer delete(data)
	for i in 0 ..< 8 {
		data[i] = u8(i)
	}

	testing.expect_value(t, entropy_output(data, path), "")
	expect_near(t, calculate_entropy(data), 3.0)

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "Classification: Low entropy (text/code)\n"),
		"3.0 bits must classify as low")
}

// Brackets the 7.0 threshold from below without sitting on it.
@(test)
test_entropy_output_six_bits_is_medium :: proc(t: ^testing.T) {
	path := tmp_path("entropy_six_bits")
	defer drop(path)

	data := make([]u8, 64)
	defer delete(data)
	for i in 0 ..< 64 {
		data[i] = u8(i)
	}

	testing.expect_value(t, entropy_output(data, path), "")
	expect_near(t, calculate_entropy(data), 6.0)

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "Classification: Medium entropy (mixed)\n"),
		"6.0 bits must classify as medium")
}

@(test)
test_entropy_output_reports_open_failure :: proc(t: ^testing.T) {
	err := entropy_output([]u8{1, 2, 3}, "/draugr_no_such_dir_4c1f/entropy.txt")

	testing.expect(t, err != "", "unwritable out_path must surface an error")
}

@(test)
test_code_output_no_sections :: proc(t: ^testing.T) {
	path := tmp_path("code_none")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)

	testing.expect_value(t, code_output([]u8{}, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "no section headers"), "must fall back to segments")
	testing.expect(t, strings.contains(got, "no PT_GNU_EH_FRAME"), "must report missing eh_frame_hdr")
}

@(test)
test_code_output_lists_only_executable_sections :: proc(t: ^testing.T) {
	path := tmp_path("code_exec")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	info.shstrtab = SHSTRTAB[:]

	append(&info.section_hdrs, elf.Section_Header{type = elf.SHT_NULL})
	append(&info.section_hdrs, elf.Section_Header{
		name = 1, type = elf.SHT_PROGBITS, flags = elf.SHF_EXECINSTR,
		addr = 0x401000, offset = 0, size = 4,
	})
	append(&info.section_hdrs, elf.Section_Header{
		name = 7, type = elf.SHT_PROGBITS, flags = 0,
		addr = 0x402000, offset = 4, size = 4,
	})

	data := []u8{0x90, 0x90, 0xc3, 0x00, 0xde, 0xad, 0xbe, 0xef}
	testing.expect_value(t, code_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, ".text"), ".text must be listed")
	testing.expect(t, !strings.contains(got, ".data"), "non-executable sections must be skipped")
}

@(test)
test_code_output_skips_nobits_and_out_of_file_sections :: proc(t: ^testing.T) {
	path := tmp_path("code_nobits")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	info.shstrtab = SHSTRTAB[:]

	append(&info.section_hdrs, elf.Section_Header{
		name = 1, type = elf.SHT_NOBITS, flags = elf.SHF_EXECINSTR, size = 100,
	})
	append(&info.section_hdrs, elf.Section_Header{
		name = 7, type = elf.SHT_PROGBITS, flags = elf.SHF_EXECINSTR,
		offset = 1000, size = 4,
	})

	data := []u8{1, 2, 3, 4}
	testing.expect_value(t, code_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, !strings.contains(got, ".text"), "SHT_NOBITS must be skipped")
	testing.expect(t, strings.contains(got, ".data"), "out-of-file section is still listed")
	testing.expect(t, strings.contains(got, "0.00"), "unreadable section entropy is zero")
}

@(test)
test_code_output_flags_entry_outside_pt_load :: proc(t: ^testing.T) {
	path := tmp_path("code_entry_out")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	info.header.entry = 0xdeadbeef
	append(&info.program_hdrs, elf.Program_Header{
		type = elf.PT_LOAD, vaddr = 0x400000, memsz = 0x1000, flags = elf.PF_R | elf.PF_X,
	})

	testing.expect_value(t, code_output([]u8{}, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "outside every PT_LOAD"), "must flag unmapped entry")
}

@(test)
test_code_output_flags_entry_in_non_executable_segment :: proc(t: ^testing.T) {
	path := tmp_path("code_entry_nx")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	info.header.entry = 0x400100
	append(&info.program_hdrs, elf.Program_Header{
		type = elf.PT_LOAD, vaddr = 0x400000, memsz = 0x1000, flags = elf.PF_R | elf.PF_W,
	})

	testing.expect_value(t, code_output([]u8{}, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "non-executable segment"), "must flag NX entry")
}

MAP_HEAD :: "ELF Memory Map\n" +
            "==============\n\n" +
            "File Layout:\n" +
            DASH42 + "\n" +
            "0x00000000: ELF Header (64 bytes)\n"

MAP_SEG_HEAD :: "Segments:\n" +
                "Type" + SP10 + "Offset" + SP5 + "VirtAddr" + SP3 +
                "FileSize" + SP3 + "MemSize" + SP4 + "Flags\n" +
                DASH69 + "\n"

MAP_SEC_HEAD :: "Sections:\n" +
                "Name" + SP13 + "Type" + SP7 + "Addr" + SP7 + "Offset" + SP5 + "Size\n" +
                DASH60 + "\n"

@(test)
test_map_output_no_segments_no_sections :: proc(t: ^testing.T) {
	path := tmp_path("map_empty")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)

	data := make([]u8, 32)
	defer delete(data)

	testing.expect_value(t, map_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect_value(t, got,
		MAP_HEAD +
		"0x00000020: EOF (file size: 32 bytes)\n\n" +
		MAP_SEG_HEAD + "\n" +
		MAP_SEC_HEAD)
}

@(test)
test_map_output_empty_data_no_segments :: proc(t: ^testing.T) {
	path := tmp_path("map_empty_data")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)

	testing.expect_value(t, map_output([]u8{}, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "0x00000000: EOF (file size: 0 bytes)\n"),
		"empty file must still report an EOF marker")
}

@(test)
test_map_output_header_table_offsets :: proc(t: ^testing.T) {
	path := tmp_path("map_headers")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	info.header.phoff = 64
	info.header.phnum = 2
	info.header.phentsize = 56
	info.header.shoff = 1000
	info.header.shnum = 3
	info.header.shentsize = 64
	for _ in 0 ..< 2 { append(&info.program_hdrs, elf.Program_Header{}) }
	for _ in 0 ..< 3 { append(&info.section_hdrs, elf.Section_Header{}) }

	data := make([]u8, 2048)
	defer delete(data)

	testing.expect_value(t, map_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got,
		"0x00000040: Program Headers\n" +
		"0x000000b0: Program Headers End\n" +
		"0x000003e8: Section Headers\n" +
		"0x000004a8: Section Headers End\n"),
		"header table extents must be derived from phoff/phnum/phentsize and shoff/shnum/shentsize")
}

@(test)
test_map_output_segment_row_and_bar :: proc(t: ^testing.T) {
	path := tmp_path("map_segments")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	append(&info.program_hdrs, elf.Program_Header{
		type   = elf.PT_LOAD,
		flags  = elf.PF_R | elf.PF_X,
		offset = 0,
		vaddr  = 0x400000,
		filesz = 50,
		memsz  = 50,
	})
	append(&info.program_hdrs, elf.Program_Header{
		type   = elf.PT_LOAD,
		flags  = elf.PF_R | elf.PF_W,
		offset = 50,
		vaddr  = 0x600000,
		filesz = 50,
		memsz  = 50,
	})

	data := make([]u8, 100)
	defer delete(data)

	testing.expect_value(t, map_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got,
		"LOAD" + SP10 + "0x00000000 0x00400000 0x00000032 0x00000032 R X\n" +
		"  [|" + HASH25 + DASH25 + "|]\n" +
		"LOAD" + SP10 + "0x00000032 0x00600000 0x00000032 0x00000032 RW \n" +
		"  [|" + DASH25 + HASH25 + "|]\n"),
		"segment rows and coverage bars must match the file layout")
}

@(test)
test_map_output_bar_saturates_on_tiny_file :: proc(t: ^testing.T) {
	path := tmp_path("map_tiny")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	append(&info.program_hdrs, elf.Program_Header{type = elf.PT_LOAD, filesz = 1, memsz = 1})

	data := []u8{0x7f}
	testing.expect_value(t, map_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "  [|" + HASH50 + "|]\n"),
		"a segment covering the whole file must fill the bar")
}

@(test)
test_map_output_skips_bar_for_pt_null :: proc(t: ^testing.T) {
	path := tmp_path("map_pt_null")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	append(&info.program_hdrs, elf.Program_Header{type = elf.PT_NULL, filesz = 8, memsz = 8})

	data := make([]u8, 16)
	defer delete(data)

	testing.expect_value(t, map_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "NULL"), "PT_NULL row must still be listed")
	testing.expect(t, !strings.contains(got, "  [|"), "PT_NULL must not draw a bar")
}

@(test)
test_map_output_empty_data_draws_no_bar :: proc(t: ^testing.T) {
	path := tmp_path("map_empty_bar")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	append(&info.program_hdrs, elf.Program_Header{type = elf.PT_LOAD, filesz = 1, memsz = 1})

	testing.expect_value(t, map_output([]u8{}, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, !strings.contains(got, "  [|"), "empty data must not draw a bar")
}

@(test)
test_map_output_section_rows :: proc(t: ^testing.T) {
	path := tmp_path("map_sections")
	defer drop(path)

	info := new_info()
	defer elf.destroy(&info)
	info.shstrtab = SHSTRTAB[:]
	append(&info.section_hdrs, elf.Section_Header{
		name   = 1,
		type   = elf.SHT_PROGBITS,
		addr   = 0x401000,
		offset = 0,
		size   = 4,
	})

	data := make([]u8, 8)
	defer delete(data)

	testing.expect_value(t, map_output(data, &info, path), "")

	got := read_all(t, path)
	defer delete(got)
	testing.expect(t, strings.contains(got,
		".text" + SP12 + "PROGBITS" + SP3 + "0x00401000 0x00000000 0x4\n"),
		"section row must render name, type, addr, offset and size")
}

@(test)
test_map_output_reports_open_failure :: proc(t: ^testing.T) {
	info := new_info()
	defer elf.destroy(&info)

	err := map_output([]u8{}, &info, "/draugr_no_such_dir_4c1f/map.txt")

	testing.expect(t, err != "", "unwritable out_path must surface an error")
}

@(test)
test_bin_diff_missing_reference :: proc(t: ^testing.T) {
	info := new_info()
	defer elf.destroy(&info)

	err := bin_diff_output([]u8{}, &info, "/draugr_no_such_file_4c1f", "")
	testing.expect(t, strings.contains(err, "failed to read"), "missing reference must surface an error")
}

@(test)
test_bin_diff_non_elf_reference :: proc(t: ^testing.T) {
	path := tmp_path("bindiff_notelf")
	defer drop(path)
	_ = os.write_entire_file(path, []u8{'n', 'o', 'p', 'e'})

	info := new_info()
	defer elf.destroy(&info)

	err := bin_diff_output([]u8{}, &info, path, "")
	testing.expect(t, strings.contains(err, "not an ELF"), "non-ELF reference must surface an error")
}

@(test)
test_bin_diff_reports_section_and_dependency_changes :: proc(t: ^testing.T) {
	ref_path := tmp_path("bindiff_ref")
	defer drop(ref_path)
	out_path := tmp_path("bindiff_out")
	defer drop(out_path)

	ref := elf.build_dynamic_elf(true, true, elf.DEFAULT_DYN_ENTRIES[:])
	defer delete(ref)
	_ = os.write_entire_file(ref_path, ref)

	entries := [][2]u64{
		{elf.DT_NEEDED, elf.DYN_OFF_NEEDED_1},
		{elf.DT_STRTAB, elf.DYN_BASE + 0x200},
		{elf.DT_STRSZ,  u64(len(elf.DYN_STR))},
		{elf.DT_NULL,   0},
	}
	mine := elf.build_dynamic_elf(true, true, entries[:])
	defer delete(mine)

	info, _ := elf.load(mine)
	defer elf.destroy(&info)

	testing.expect_value(t, bin_diff_output(mine, &info, ref_path, out_path), "")

	got := read_all(t, out_path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "+ libc.so.6"), "reference-only dependency must show as added")
	testing.expect(t, strings.contains(got, "/opt/runpath"), "runpath change must be reported")
}

@(test)
test_bin_diff_identical_files_report_no_changes :: proc(t: ^testing.T) {
	ref_path := tmp_path("bindiff_same_ref")
	defer drop(ref_path)
	out_path := tmp_path("bindiff_same_out")
	defer drop(out_path)

	img := elf.build_dynamic_elf(true, true, elf.DEFAULT_DYN_ENTRIES[:])
	defer delete(img)
	_ = os.write_entire_file(ref_path, img)

	info, _ := elf.load(img)
	defer elf.destroy(&info)

	testing.expect_value(t, bin_diff_output(img, &info, ref_path, out_path), "")

	got := read_all(t, out_path)
	defer delete(got)
	testing.expect(t, strings.contains(got, "unchanged"), "identical dependencies must report unchanged")
	testing.expect(t, !strings.contains(got, "->"), "identical files must show no deltas")
}
