package elf

import "core:testing"

DYN_BASE :: 0x400000
DYN_STR  :: "\x00libtest.so.1\x00libc.so.6\x00/opt/rpath\x00/opt/runpath\x00"

DYN_OFF_NEEDED_1 :: 1
DYN_OFF_NEEDED_2 :: 14
DYN_OFF_RPATH    :: 24
DYN_OFF_RUNPATH  :: 35

build_dynamic_elf :: proc(is64: bool, little: bool, entries: [][2]u64) -> []u8 {
	dyn_off  :: 0x100
	str_off  :: 0x200
	total    :: 0x300

	ph_off   := 64 if is64 else 52
	ph_size  := PHDR_SIZE_64 if is64 else PHDR_SIZE_32
	ent_size := 16 if is64 else 8

	data := make([]u8, total)
	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = ELF_CLASS_64 if is64 else ELF_CLASS_32
	data[5] = ELF_DATA_LSB if little else ELF_DATA_MSB
	data[6] = 1

	put_u16(data, 16, ET_DYN, little)
	put_u16(data, 18, EM_X86_64 if is64 else EM_ARM, little)

	if is64 {
		put_u64(data, 32, u64(ph_off), little)
		put_u64(data, 40, 0, little)
		put_u16(data, 54, u16(ph_size), little)
		put_u16(data, 56, 2, little)
	} else {
		put_u32(data, 28, u32(ph_off), little)
		put_u32(data, 32, 0, little)
		put_u16(data, 42, u16(ph_size), little)
		put_u16(data, 44, 2, little)
	}

	write_phdr(data, ph_off, is64, little, Program_Header{
		type = PT_LOAD, offset = 0, vaddr = DYN_BASE,
		filesz = total, memsz = total, flags = PF_R | PF_X, align = 0x1000,
	})
	write_phdr(data, ph_off + ph_size, is64, little, Program_Header{
		type = PT_DYNAMIC, offset = dyn_off, vaddr = DYN_BASE + dyn_off,
		filesz = u64(len(entries) * ent_size), memsz = u64(len(entries) * ent_size),
		flags = PF_R | PF_W, align = 8,
	})

	pos := dyn_off
	for e in entries {
		if is64 {
			put_u64(data, pos, e[0], little)
			put_u64(data, pos + 8, e[1], little)
		} else {
			put_u32(data, pos, u32(e[0]), little)
			put_u32(data, pos + 4, u32(e[1]), little)
		}
		pos += ent_size
	}

	copy(data[str_off:], DYN_STR)
	return data
}

DEFAULT_DYN_ENTRIES := [?][2]u64{
	{DT_NEEDED,  DYN_OFF_NEEDED_1},
	{DT_NEEDED,  DYN_OFF_NEEDED_2},
	{DT_SONAME,  DYN_OFF_NEEDED_1},
	{DT_RPATH,   DYN_OFF_RPATH},
	{DT_RUNPATH, DYN_OFF_RUNPATH},
	{DT_STRTAB,  DYN_BASE + 0x200},
	{DT_STRSZ,   u64(len(DYN_STR))},
	{DT_NULL,    0},
}

check_dynamic :: proc(t: ^testing.T, is64: bool, little: bool) {
	data := build_dynamic_elf(is64, little, DEFAULT_DYN_ENTRIES[:])
	defer delete(data)

	info, err := load(data)
	defer destroy(&info)

	testing.expect_value(t, err, "")
	testing.expect_value(t, len(info.dyn_entries), 7)
	testing.expect_value(t, len(info.needed), 2)
	testing.expect_value(t, info.needed[0], "libtest.so.1")
	testing.expect_value(t, info.needed[1], "libc.so.6")
	testing.expect_value(t, info.soname, "libtest.so.1")
	testing.expect_value(t, info.rpath, "/opt/rpath")
	testing.expect_value(t, info.runpath, "/opt/runpath")
}

@(test)
test_dynamic_elf64_le :: proc(t: ^testing.T) { check_dynamic(t, true,  true)  }

@(test)
test_dynamic_elf64_be :: proc(t: ^testing.T) { check_dynamic(t, true,  false) }

@(test)
test_dynamic_elf32_le :: proc(t: ^testing.T) { check_dynamic(t, false, true)  }

@(test)
test_dynamic_elf32_be :: proc(t: ^testing.T) { check_dynamic(t, false, false) }

@(test)
test_dynamic_stops_at_dt_null :: proc(t: ^testing.T) {
	entries := [][2]u64{
		{DT_NEEDED, DYN_OFF_NEEDED_1},
		{DT_STRTAB, DYN_BASE + 0x200},
		{DT_STRSZ,  u64(len(DYN_STR))},
		{DT_NULL,   0},
		{DT_NEEDED, DYN_OFF_NEEDED_2},
	}
	data := build_dynamic_elf(true, true, entries[:])
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	testing.expect_value(t, len(info.needed), 1)
	testing.expect_value(t, info.needed[0], "libtest.so.1")
}

@(test)
test_dynamic_strtab_outside_file_is_ignored :: proc(t: ^testing.T) {
	entries := [][2]u64{
		{DT_NEEDED, DYN_OFF_NEEDED_1},
		{DT_STRTAB, DYN_BASE + 0xdeadbeef},
		{DT_STRSZ,  u64(len(DYN_STR))},
		{DT_NULL,   0},
	}
	data := build_dynamic_elf(true, true, entries[:])
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	testing.expect_value(t, len(info.dyn_entries), 3)
	testing.expect_value(t, len(info.needed), 0)
}

@(test)
test_vaddr_to_offset_maps_through_pt_load :: proc(t: ^testing.T) {
	data := build_dynamic_elf(true, true, DEFAULT_DYN_ENTRIES[:])
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	off, ok := vaddr_to_offset(&info, DYN_BASE + 0x200)
	testing.expect(t, ok, "vaddr inside PT_LOAD must resolve")
	testing.expect_value(t, off, 0x200)

	_, miss := vaddr_to_offset(&info, DYN_BASE + 0x99999)
	testing.expect(t, !miss, "vaddr outside every PT_LOAD must fail")
}

@(test)
test_no_phantom_sections_when_shoff_zero :: proc(t: ^testing.T) {
	data := build_dynamic_elf(true, true, DEFAULT_DYN_ENTRIES[:])
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	testing.expect_value(t, len(info.section_hdrs), 0)
}

@(test)
test_dyn_tag_str_unknown_falls_back_to_hex :: proc(t: ^testing.T) {
	testing.expect_value(t, dyn_tag_str(DT_RUNPATH), "RUNPATH")
	testing.expect_value(t, dyn_tag_str(DT_VERNEEDNUM), "VERNEEDNUM")
	testing.expect_value(t, dyn_tag_str(0x70000001), "0x70000001")
}
