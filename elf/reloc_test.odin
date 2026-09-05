package elf

import "core:testing"

build_relr_elf :: proc(is64: bool, little: bool, words: []u64) -> []u8 {
	dyn_off  :: 0x100
	relr_off :: 0x200
	total    :: 0x300

	ph_off   := 64 if is64 else 52
	ph_size  := PHDR_SIZE_64 if is64 else PHDR_SIZE_32
	word     := 8 if is64 else 4

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
		put_u16(data, 54, u16(ph_size), little)
		put_u16(data, 56, 2, little)
	} else {
		put_u32(data, 28, u32(ph_off), little)
		put_u16(data, 42, u16(ph_size), little)
		put_u16(data, 44, 2, little)
	}

	write_phdr(data, ph_off, is64, little, Program_Header{
		type = PT_LOAD, offset = 0, vaddr = DYN_BASE,
		filesz = total, memsz = total, flags = PF_R | PF_X, align = 0x1000,
	})

	write_phdr(data, ph_off + ph_size, is64, little, Program_Header{
		type = PT_DYNAMIC, offset = dyn_off, vaddr = DYN_BASE + dyn_off,
		filesz = 64, memsz = 64, flags = PF_R, align = 8,
	})

	ent := 16 if is64 else 8
	dyn := [][2]u64{
		{DT_RELR,    DYN_BASE + relr_off},
		{DT_RELRSZ,  u64(len(words) * word)},
		{DT_RELRENT, u64(word)},
		{DT_NULL,    0},
	}
	pos := dyn_off
	for e in dyn {
		if is64 {
			put_u64(data, pos, e[0], little)
			put_u64(data, pos + 8, e[1], little)
		} else {
			put_u32(data, pos, u32(e[0]), little)
			put_u32(data, pos + 4, u32(e[1]), little)
		}
		pos += ent
	}

	pos = relr_off
	for w in words {
		if is64 {
			put_u64(data, pos, w, little)
		} else {
			put_u32(data, pos, u32(w), little)
		}
		pos += word
	}
	return data
}

@(test)
test_relr_decodes_address_then_bitmap :: proc(t: ^testing.T) {
	words := []u64{0x3da0, 0x03, 0x8001}
	data := build_relr_elf(true, true, words)
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	testing.expect_value(t, len(info.relocs), 3)
	testing.expect_value(t, info.relocs[0].offset, 0x3da0)
	testing.expect_value(t, info.relocs[1].offset, 0x3da8)
	testing.expect_value(t, info.relocs[2].offset, 0x4010)

	for r in info.relocs {
		testing.expect_value(t, r.type, u32(R_X86_64_RELATIVE))
		testing.expect_value(t, r.kind, Reloc_Source.Relr)
	}
}

@(test)
test_relr_empty_bitmap_emits_nothing :: proc(t: ^testing.T) {
	words := []u64{0x1000, 0x01}
	data := build_relr_elf(true, true, words)
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	testing.expect_value(t, len(info.relocs), 1)
	testing.expect_value(t, info.relocs[0].offset, 0x1000)
}

@(test)
test_relr_big_endian :: proc(t: ^testing.T) {
	words := []u64{0x2000, 0x07}
	data := build_relr_elf(true, false, words)
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	testing.expect_value(t, len(info.relocs), 3)
	testing.expect_value(t, info.relocs[0].offset, 0x2000)
	testing.expect_value(t, info.relocs[1].offset, 0x2008)
	testing.expect_value(t, info.relocs[2].offset, 0x2010)
}

@(test)
test_reloc_info_split_differs_by_class :: proc(t: ^testing.T) {
	testing.expect_value(t, reloc_type_str(EM_X86_64, 7), "R_X86_64_JUMP_SLOT")
	testing.expect_value(t, reloc_type_str(EM_AARCH64, 1026), "R_AARCH64_JUMP_SLOT")
	testing.expect_value(t, reloc_type_str(EM_X86_64, 999), "999")

	testing.expect(t, is_jump_slot(EM_X86_64, 7), "x86-64 JUMP_SLOT")
	testing.expect(t, is_jump_slot(EM_AARCH64, 1026), "aarch64 JUMP_SLOT")
	testing.expect(t, !is_jump_slot(EM_X86_64, 8), "RELATIVE is not a jump slot")
}
