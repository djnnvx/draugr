package elf

import "core:mem"
import "core:testing"

make_elf64_header :: proc(data: []u8, etype: u16, machine: u16) {
	data[0] = 0x7f
	data[1] = 0x45
	data[2] = 0x4c
	data[3] = 0x46
	data[4] = ELF_CLASS_64
	data[5] = ELF_DATA_LSB
	data[6] = 1
	data[7] = 0
	
	data[16] = u8(etype)
	data[17] = u8(etype >> 8)
	data[18] = u8(machine)
	data[19] = u8(machine >> 8)
	data[24] = 0x00
	data[25] = 0x00
	data[26] = 0x40
	data[27] = 0x00
	data[32] = 64
	data[33] = 0
	data[52] = 64
	data[53] = 0
	data[54] = 56
	data[55] = 0
	data[58] = 64
	data[59] = 0
}

@(test)
test_probe_elf64 :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_X86_64)
	
	result := probe(data)
	testing.expect(t, result == true, "should recognize ELF64 header")
}

@(test)
test_probe_elf32 :: proc(t: ^testing.T) {
	data := make([]u8, 52)
	defer delete(data)
	
	data[0] = 0x7f
	data[1] = 0x45
	data[2] = 0x4c
	data[3] = 0x46
	data[4] = ELF_CLASS_32
	data[5] = ELF_DATA_LSB
	
	result := probe(data)
	testing.expect(t, result == true, "should recognize ELF32 header")
}

@(test)
test_probe_invalid_magic :: proc(t: ^testing.T) {
	data := []u8{0x00, 0x01, 0x02, 0x03}
	
	result := probe(data)
	testing.expect(t, result == false, "should reject invalid magic")
}

@(test)
test_probe_too_small :: proc(t: ^testing.T) {
	data := []u8{0x7f, 0x45, 0x4c}
	
	result := probe(data)
	testing.expect(t, result == false, "should reject data smaller than 16 bytes")
}

@(test)
test_parse_header_class_64 :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_X86_64)
	
	header, err := parse_header(data)
	testing.expect(t, err == "", "parse should succeed")
	testing.expect(t, header.class == ELF_CLASS_64, "class should be 64")
}

@(test)
test_parse_header_class_32 :: proc(t: ^testing.T) {
	data := make([]u8, 52)
	defer delete(data)
	
	data[0] = 0x7f
	data[1] = 0x45
	data[2] = 0x4c
	data[3] = 0x46
	data[4] = ELF_CLASS_32
	data[5] = ELF_DATA_LSB
	data[16] = u8(ET_EXEC)
	data[17] = 0
	data[18] = u8(EM_386)
	data[19] = 0
	
	header, err := parse_header(data)
	testing.expect(t, err == "", "parse should succeed")
	testing.expect(t, header.class == ELF_CLASS_32, "class should be 32")
}

@(test)
test_parse_header_type_exec :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_X86_64)
	
	header, err := parse_header(data)
	
	testing.expect(t, err == "")
	testing.expect(t, header.type == ET_EXEC, "type should be ET_EXEC")
}

@(test)
test_parse_header_type_dyn :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_DYN, EM_X86_64)
	
	header, err := parse_header(data)
	
	testing.expect(t, err == "")
	testing.expect(t, header.type == ET_DYN, "type should be ET_DYN")
}

@(test)
test_parse_header_type_rel :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_REL, EM_X86_64)
	
	header, err := parse_header(data)
	
	testing.expect(t, err == "")
	testing.expect(t, header.type == ET_REL, "type should be ET_REL")
}

@(test)
test_parse_header_machine_x86_64 :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_X86_64)
	
	header, err := parse_header(data)
	
	testing.expect(t, err == "")
	testing.expect(t, header.machine == EM_X86_64, "machine should be x86-64")
}

@(test)
test_parse_header_machine_arm :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_ARM)
	
	header, err := parse_header(data)
	
	testing.expect(t, err == "")
	testing.expect(t, header.machine == EM_ARM, "machine should be ARM")
}

@(test)
test_parse_header_machine_aarch64 :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_AARCH64)
	
	header, err := parse_header(data)
	
	testing.expect(t, err == "")
	testing.expect(t, header.machine == EM_AARCH64, "machine should be AArch64")
}

@(test)
test_parse_header_machine_riscv :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_RISCV)

	header, err := parse_header(data)

	testing.expect(t, err == "")
	testing.expect(t, header.machine == EM_RISCV, "machine should be RISC-V")
}

@(test)
test_machine_str_covers_firmware_arches :: proc(t: ^testing.T) {
	testing.expect_value(t, machine_to_str(EM_MIPS), "MIPS")
	testing.expect_value(t, machine_to_str(EM_PPC), "PowerPC")
	testing.expect_value(t, machine_to_str(EM_PPC64), "PowerPC64")
	testing.expect_value(t, machine_to_str(EM_ARM), "ARM")
	testing.expect_value(t, machine_to_str(EM_AARCH64), "AArch64")
}

@(test)
test_read_u16_le_basic :: proc(t: ^testing.T) {
	data := []u8{0x01, 0x02}
	
	val := read_u16(data, 0, .Little)
	testing.expect_value(t, val, u16(0x0201))
}

@(test)
test_read_u16_le_offset :: proc(t: ^testing.T) {
	data := []u8{0x00, 0x00, 0x01, 0x02}
	
	val := read_u16(data, 2, .Little)
	testing.expect_value(t, val, u16(0x0201))
}

@(test)
test_read_u32_le_basic :: proc(t: ^testing.T) {
	data := []u8{0x01, 0x02, 0x03, 0x04}
	
	val := read_u32(data, 0, .Little)
	testing.expect_value(t, val, u32(0x04030201))
}

@(test)
test_read_u64_le_basic :: proc(t: ^testing.T) {
	data := []u8{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	
	val := read_u64(data, 0, .Little)
	testing.expect_value(t, val, u64(0x0807060504030201))
}

@(test)
test_read_u16_be_basic :: proc(t: ^testing.T) {
	data := []u8{0x01, 0x02}
	
	val := read_u16(data, 0, .Big)
	testing.expect_value(t, val, u16(0x0102))
}

@(test)
test_read_u32_be_basic :: proc(t: ^testing.T) {
	data := []u8{0x01, 0x02, 0x03, 0x04}
	
	val := read_u32(data, 0, .Big)
	testing.expect_value(t, val, u32(0x01020304))
}

@(test)
test_read_u64_be_basic :: proc(t: ^testing.T) {
	data := []u8{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	
	val := read_u64(data, 0, .Big)
	testing.expect_value(t, val, u64(0x0102030405060708))
}

@(test)
test_load_elf64_basic :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_X86_64)
	
	info, err := load(data)
	defer destroy(&info)
	testing.expect(t, err == "", "load should succeed")
	testing.expect(t, info.is_64bit == true, "should be 64-bit")
	testing.expect(t, info.is_pie == false, "ET_EXEC should not be PIE")
}

@(test)
test_load_elf64_pie :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_DYN, EM_X86_64)
	
	info, err := load(data)
	defer destroy(&info)
	testing.expect(t, err == "", "load should succeed")
	testing.expect(t, info.is_pie == true, "ET_DYN should be PIE")
}

@(test)
test_load_elf32_basic :: proc(t: ^testing.T) {
	data := make([]u8, 52)
	defer delete(data)
	
	data[0] = 0x7f
	data[1] = 0x45
	data[2] = 0x4c
	data[3] = 0x46
	data[4] = ELF_CLASS_32
	data[5] = ELF_DATA_LSB
	data[16] = u8(ET_EXEC)
	data[17] = 0
	data[18] = u8(EM_386)
	data[19] = 0
	
	info, err := load(data)
	defer destroy(&info)
	testing.expect(t, err == "", "load should succeed")
	testing.expect(t, info.is_64bit == false, "should be 32-bit")
}

TEXT_BLOB     :: "\x55\x89\xe5\x83\xec\x08\xc9\xc3"
INTERP_BLOB   :: "/lib/ld-linux.so.2\x00"
SHSTRTAB_BLOB :: "\x00.text\x00.interp\x00.symtab\x00.strtab\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
STRTAB_BLOB   :: "\x00main\x00counter\x00printf\x00"
DYNSTR_BLOB   :: "\x00puts\x00"

NAME_TEXT     :: 1
NAME_INTERP   :: 7
NAME_SYMTAB   :: 15
NAME_STRTAB   :: 23
NAME_DYNSYM   :: 31
NAME_DYNSTR   :: 39
NAME_SHSTRTAB :: 47

STR_MAIN    :: 1
STR_COUNTER :: 6
STR_PRINTF  :: 14
DYN_PUTS    :: 1

SEC_NULL     :: 0
SEC_TEXT     :: 1
SEC_INTERP   :: 2
SEC_SYMTAB   :: 3
SEC_STRTAB   :: 4
SEC_DYNSYM   :: 5
SEC_DYNSTR   :: 6
SEC_SHSTRTAB :: 7

Raw_Sym :: struct {
	name  : u32,
	info  : u8,
	other : u8,
	shndx : u16,
	value : u64,
	size  : u64,
}

Fixture :: struct {
	data      : []u8,
	class     : u8,
	endian    : u8,
	type      : u16,
	machine   : u16,
	entry     : u64,
	flags     : u32,
	phoff     : u64,
	shoff     : u64,
	phentsize : u16,
	shentsize : u16,
	phnum     : u16,
	shnum     : u16,
	shstrndx  : u16,
	symsize   : int,
	interp_off: u64,
	segments  : [4]Program_Header,
	sections  : [8]Section_Header,
	symbols   : [4]Raw_Sym,
	dynsyms   : [2]Raw_Sym,
}

put_u16 :: proc(data: []u8, off: int, v: u16, little: bool) {
	if little {
		data[off+0] = u8(v)
		data[off+1] = u8(v >> 8)
	} else {
		data[off+0] = u8(v >> 8)
		data[off+1] = u8(v)
	}
}

put_u32 :: proc(data: []u8, off: int, v: u32, little: bool) {
	for i in 0 ..< 4 {
		shift := uint(8 * i) if little else uint(8 * (3 - i))
		data[off+i] = u8(v >> shift)
	}
}

put_u64 :: proc(data: []u8, off: int, v: u64, little: bool) {
	for i in 0 ..< 8 {
		shift := uint(8 * i) if little else uint(8 * (7 - i))
		data[off+i] = u8(v >> shift)
	}
}

align_up :: proc(v: int, a: int) -> int {
	return (v + a - 1) / a * a
}

write_phdr :: proc(data: []u8, off: int, is64: bool, little: bool, p: Program_Header) {
	if is64 {
		put_u32(data, off+0,  p.type, little)
		put_u32(data, off+4,  u32(p.flags), little)
		put_u64(data, off+8,  p.offset, little)
		put_u64(data, off+16, p.vaddr, little)
		put_u64(data, off+24, p.paddr, little)
		put_u64(data, off+32, p.filesz, little)
		put_u64(data, off+40, p.memsz, little)
		put_u64(data, off+48, p.align, little)
	} else {
		put_u32(data, off+0,  p.type, little)
		put_u32(data, off+4,  u32(p.offset), little)
		put_u32(data, off+8,  u32(p.vaddr), little)
		put_u32(data, off+12, u32(p.paddr), little)
		put_u32(data, off+16, u32(p.filesz), little)
		put_u32(data, off+20, u32(p.memsz), little)
		put_u32(data, off+24, u32(p.flags), little)
		put_u32(data, off+28, u32(p.align), little)
	}
}

write_shdr :: proc(data: []u8, off: int, is64: bool, little: bool, s: Section_Header) {
	if is64 {
		put_u32(data, off+0,  s.name, little)
		put_u32(data, off+4,  s.type, little)
		put_u64(data, off+8,  s.flags, little)
		put_u64(data, off+16, s.addr, little)
		put_u64(data, off+24, s.offset, little)
		put_u64(data, off+32, s.size, little)
		put_u32(data, off+40, s.link, little)
		put_u32(data, off+44, s.info, little)
		put_u64(data, off+48, s.addralign, little)
		put_u64(data, off+56, s.entsize, little)
	} else {
		put_u32(data, off+0,  s.name, little)
		put_u32(data, off+4,  s.type, little)
		put_u32(data, off+8,  u32(s.flags), little)
		put_u32(data, off+12, u32(s.addr), little)
		put_u32(data, off+16, u32(s.offset), little)
		put_u32(data, off+20, u32(s.size), little)
		put_u32(data, off+24, s.link, little)
		put_u32(data, off+28, s.info, little)
		put_u32(data, off+32, u32(s.addralign), little)
		put_u32(data, off+36, u32(s.entsize), little)
	}
}

write_sym :: proc(data: []u8, off: int, is64: bool, little: bool, s: Raw_Sym) {
	if is64 {
		put_u32(data, off+0,  s.name, little)
		data[off+4] = s.info
		data[off+5] = s.other
		put_u16(data, off+6,  s.shndx, little)
		put_u64(data, off+8,  s.value, little)
		put_u64(data, off+16, s.size, little)
	} else {
		put_u32(data, off+0,  s.name, little)
		put_u32(data, off+4,  u32(s.value), little)
		put_u32(data, off+8,  u32(s.size), little)
		data[off+12] = s.info
		data[off+13] = s.other
		put_u16(data, off+14, s.shndx, little)
	}
}

build_elf :: proc(class: u8, endian: u8) -> Fixture {
	f: Fixture
	f.class = class
	f.endian = endian

	is64 := class == ELF_CLASS_64
	little := endian == ELF_DATA_LSB

	ehsize := 64 if is64 else 52
	f.phentsize = 56 if is64 else 32
	f.shentsize = 64 if is64 else 40
	f.symsize   = 24 if is64 else 16

	f.phnum    = 4
	f.shnum    = 8
	f.shstrndx = SEC_SHSTRTAB
	f.type     = ET_EXEC
	f.machine  = EM_X86_64 if is64 else EM_386
	f.entry    = 0x0000000000401120 if is64 else 0x08049000
	f.flags    = 0x05000200

	off_ph     := ehsize
	off_interp := off_ph + int(f.phnum) * int(f.phentsize)
	off_text   := off_interp + len(INTERP_BLOB)
	off_shstr  := off_text + len(TEXT_BLOB)
	off_strtab := off_shstr + len(SHSTRTAB_BLOB)
	off_dynstr := off_strtab + len(STRTAB_BLOB)
	off_symtab := align_up(off_dynstr + len(DYNSTR_BLOB), 8)
	off_dynsym := off_symtab + 4 * f.symsize
	off_sh     := align_up(off_dynsym + 2 * f.symsize, 8)
	total      := off_sh + int(f.shnum) * int(f.shentsize)

	f.phoff = u64(off_ph)
	f.shoff = u64(off_sh)
	f.interp_off = u64(off_interp)

	f.segments = [4]Program_Header{
		{
			type = PT_LOAD, flags = PF_R | PF_X,
			offset = 0, vaddr = 0x08048000, paddr = 0x08048000,
			filesz = 0x0640, memsz = 0x0640, align = 0x1000,
		},
		{
			type = PT_LOAD, flags = PF_R | PF_W,
			offset = 0x0f00, vaddr = 0x0804af00, paddr = 0x0804af10,
			filesz = 0x0118, memsz = 0x0220, align = 0x1000,
		},
		{
			type = PT_INTERP, flags = PF_R,
			offset = u64(off_interp), vaddr = 0x08048154, paddr = 0x08048154,
			filesz = u64(len(INTERP_BLOB)), memsz = u64(len(INTERP_BLOB)), align = 1,
		},
		{
			type = PT_DYNAMIC, flags = PF_R | PF_W,
			offset = 0x0f14, vaddr = 0x0804af14, paddr = 0x0804af18,
			filesz = 0x00e8, memsz = 0x00e8, align = 4,
		},
	}

	f.sections = [8]Section_Header{
		{},
		{
			name = NAME_TEXT, type = SHT_PROGBITS, flags = 0x6, addr = 0x08049000,
			offset = u64(off_text), size = u64(len(TEXT_BLOB)), addralign = 16,
		},
		{
			name = NAME_INTERP, type = SHT_PROGBITS, flags = 0x2, addr = 0x08048154,
			offset = u64(off_interp), size = u64(len(INTERP_BLOB)), addralign = 1,
		},
		{
			name = NAME_SYMTAB, type = SHT_SYMTAB,
			offset = u64(off_symtab), size = u64(4 * f.symsize),
			link = SEC_STRTAB, info = 2, addralign = 8, entsize = u64(f.symsize),
		},
		{
			name = NAME_STRTAB, type = SHT_STRTAB,
			offset = u64(off_strtab), size = u64(len(STRTAB_BLOB)), addralign = 1,
		},
		{
			name = NAME_DYNSYM, type = SHT_DYNSYM, flags = 0x2, addr = 0x080481b0,
			offset = u64(off_dynsym), size = u64(2 * f.symsize),
			link = SEC_DYNSTR, info = 1, addralign = 4, entsize = u64(f.symsize),
		},
		{
			name = NAME_DYNSTR, type = SHT_STRTAB, flags = 0x2, addr = 0x080481f0,
			offset = u64(off_dynstr), size = u64(len(DYNSTR_BLOB)), addralign = 1,
		},
		{
			name = NAME_SHSTRTAB, type = SHT_STRTAB,
			offset = u64(off_shstr), size = u64(len(SHSTRTAB_BLOB)), addralign = 1,
		},
	}

	f.symbols = [4]Raw_Sym{
		{},
		{name = STR_COUNTER, info = (STB_LOCAL  << 4) | STT_OBJECT, value = 0x0804af00, size = 4,    shndx = SEC_TEXT},
		{name = STR_MAIN,    info = (STB_GLOBAL << 4) | STT_FUNC,   value = 0x08049000, size = 0x40, shndx = SEC_TEXT},
		{name = STR_PRINTF,  info = (STB_GLOBAL << 4) | STT_FUNC,   value = 0,          size = 0,    shndx = 0},
	}

	f.dynsyms = [2]Raw_Sym{
		{},
		{name = DYN_PUTS, info = (STB_GLOBAL << 4) | STT_FUNC, value = 0, size = 0, shndx = 0},
	}

	data := make([]u8, total)
	f.data = data

	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = class
	data[5] = endian
	data[6] = 1
	data[7] = 0

	put_u16(data, 16, f.type, little)
	put_u16(data, 18, f.machine, little)
	put_u32(data, 20, 1, little)

	if is64 {
		put_u64(data, 24, f.entry, little)
		put_u64(data, 32, f.phoff, little)
		put_u64(data, 40, f.shoff, little)
		put_u32(data, 48, f.flags, little)
		put_u16(data, 52, u16(ehsize), little)
		put_u16(data, 54, f.phentsize, little)
		put_u16(data, 56, f.phnum, little)
		put_u16(data, 58, f.shentsize, little)
		put_u16(data, 60, f.shnum, little)
		put_u16(data, 62, f.shstrndx, little)
	} else {
		put_u32(data, 24, u32(f.entry), little)
		put_u32(data, 28, u32(f.phoff), little)
		put_u32(data, 32, u32(f.shoff), little)
		put_u32(data, 36, f.flags, little)
		put_u16(data, 40, u16(ehsize), little)
		put_u16(data, 42, f.phentsize, little)
		put_u16(data, 44, f.phnum, little)
		put_u16(data, 46, f.shentsize, little)
		put_u16(data, 48, f.shnum, little)
		put_u16(data, 50, f.shstrndx, little)
	}

	for seg, i in f.segments {
		write_phdr(data, off_ph + i * int(f.phentsize), is64, little, seg)
	}

	copy(data[off_interp:], INTERP_BLOB)
	copy(data[off_text:],   TEXT_BLOB)
	copy(data[off_shstr:],  SHSTRTAB_BLOB)
	copy(data[off_strtab:], STRTAB_BLOB)
	copy(data[off_dynstr:], DYNSTR_BLOB)

	for sym, i in f.symbols {
		write_sym(data, off_symtab + i * f.symsize, is64, little, sym)
	}
	for sym, i in f.dynsyms {
		write_sym(data, off_dynsym + i * f.symsize, is64, little, sym)
	}
	for sec, i in f.sections {
		write_shdr(data, off_sh + i * int(f.shentsize), is64, little, sec)
	}

	return f
}

SECTION_NAMES :: [8]string{"", ".text", ".interp", ".symtab", ".strtab", ".dynsym", ".dynstr", ".shstrtab"}
SYMBOL_NAMES  :: [4]string{"", "counter", "main", "printf"}
DYNSYM_NAMES  :: [2]string{"", "puts"}

check_full_image :: proc(t: ^testing.T, class: u8, endian: u8) {
	f := build_elf(class, endian)
	defer delete(f.data)

	info, err := load(f.data)
	testing.expect(t, err == "", "load should succeed")
	defer destroy(&info)

	testing.expect_value(t, info.header.class, class)
	testing.expect_value(t, info.header.data, endian)
	testing.expect_value(t, info.is_64bit, class == ELF_CLASS_64)
	testing.expect_value(t, info.is_pie, false)

	testing.expect_value(t, info.header.type, f.type)
	testing.expect_value(t, info.header.machine, f.machine)
	testing.expect_value(t, info.header.entry, f.entry)
	testing.expect_value(t, info.header.phoff, f.phoff)
	testing.expect_value(t, info.header.shoff, f.shoff)
	testing.expect_value(t, info.header.flags, f.flags)
	testing.expect_value(t, info.header.phentsize, f.phentsize)
	testing.expect_value(t, info.header.shentsize, f.shentsize)
	testing.expect_value(t, info.header.phnum, f.phnum)
	testing.expect_value(t, info.header.shnum, f.shnum)
	testing.expect_value(t, info.header.shstrndx, f.shstrndx)

	testing.expect_value(t, len(info.program_hdrs), int(f.phnum))
	if len(info.program_hdrs) == int(f.phnum) {
		for want, i in f.segments {
			testing.expect_value(t, info.program_hdrs[i], want)
		}
	}

	testing.expect_value(t, info.is_dynamic, true)
	testing.expect_value(t, info.interp_offset, f.interp_off)

	testing.expect_value(t, len(info.section_hdrs), int(f.shnum))
	if len(info.section_hdrs) == int(f.shnum) {
		names := SECTION_NAMES
		for want, i in f.sections {
			testing.expect_value(t, info.section_hdrs[i], want)
			testing.expect_value(t, get_section_name(&info, info.section_hdrs[i]), names[i])
		}
	}

	testing.expect_value(t, string(info.shstrtab), SHSTRTAB_BLOB)
	testing.expect_value(t, string(info.strtab), STRTAB_BLOB)
	testing.expect_value(t, string(info.dynstr), DYNSTR_BLOB)

	testing.expect_value(t, len(info.symbols), len(f.symbols))
	if len(info.symbols) == len(f.symbols) {
		names := SYMBOL_NAMES
		for want, i in f.symbols {
			got := info.symbols[i]
			testing.expect_value(t, got.name, names[i])
			testing.expect_value(t, got.value, want.value)
			testing.expect_value(t, got.size, want.size)
			testing.expect_value(t, got.bind, want.info >> 4)
			testing.expect_value(t, got.type, want.info & 0xf)
			testing.expect_value(t, got.shndx, want.shndx)
		}
		testing.expect_value(t, info.symbols[1].bind, u8(STB_LOCAL))
		testing.expect_value(t, info.symbols[1].type, u8(STT_OBJECT))
		testing.expect_value(t, info.symbols[2].bind, u8(STB_GLOBAL))
		testing.expect_value(t, info.symbols[2].type, u8(STT_FUNC))
		testing.expect_value(t, info.symbols[3].shndx, u16(0))
	}

	testing.expect_value(t, len(info.dyn_symbols), len(f.dynsyms))
	if len(info.dyn_symbols) == len(f.dynsyms) {
		names := DYNSYM_NAMES
		for want, i in f.dynsyms {
			got := info.dyn_symbols[i]
			testing.expect_value(t, got.name, names[i])
			testing.expect_value(t, got.bind, want.info >> 4)
			testing.expect_value(t, got.type, want.info & 0xf)
			testing.expect_value(t, got.shndx, want.shndx)
		}
	}
}

@(test)
test_full_image_elf32_le :: proc(t: ^testing.T) {
	check_full_image(t, ELF_CLASS_32, ELF_DATA_LSB)
}

@(test)
test_full_image_elf32_be :: proc(t: ^testing.T) {
	check_full_image(t, ELF_CLASS_32, ELF_DATA_MSB)
}

@(test)
test_full_image_elf64_le :: proc(t: ^testing.T) {
	check_full_image(t, ELF_CLASS_64, ELF_DATA_LSB)
}

@(test)
test_full_image_elf64_be :: proc(t: ^testing.T) {
	check_full_image(t, ELF_CLASS_64, ELF_DATA_MSB)
}

// Regression: ELF32 header fields must use the 32-bit layout

build_elf32_header_only :: proc(little: bool, entry: u32, phoff: u32, shoff: u32, flags: u32) -> []u8 {
	data := make([]u8, 52)
	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = ELF_CLASS_32
	data[5] = ELF_DATA_LSB if little else ELF_DATA_MSB
	data[6] = 1

	put_u16(data, 16, ET_EXEC, little)
	put_u16(data, 18, EM_386, little)
	put_u32(data, 20, 1, little)
	put_u32(data, 24, entry, little)
	put_u32(data, 28, phoff, little)
	put_u32(data, 32, shoff, little)
	put_u32(data, 36, flags, little)
	put_u16(data, 40, 52, little)
	put_u16(data, 42, 32, little)
	put_u16(data, 44, 9, little)
	put_u16(data, 46, 40, little)
	put_u16(data, 48, 30, little)
	put_u16(data, 50, 29, little)
	return data
}

@(test)
test_regression_elf32_header_uses_32bit_layout_le :: proc(t: ^testing.T) {
	data := build_elf32_header_only(true, 0x08049000, 52, 12620, 0)
	defer delete(data)

	h, err := parse_header(data)
	testing.expect(t, err == "", "parse should succeed")

	testing.expect_value(t, h.entry, u64(0x08049000))
	testing.expect_value(t, h.phoff, u64(52))
	testing.expect_value(t, h.shoff, u64(12620))
	testing.expect_value(t, h.flags, u32(0))
	testing.expect_value(t, h.phentsize, u16(32))
	testing.expect_value(t, h.phnum, u16(9))
	testing.expect_value(t, h.shentsize, u16(40))
	testing.expect_value(t, h.shnum, u16(30))
	testing.expect_value(t, h.shstrndx, u16(29))
}

@(test)
test_regression_elf32_header_uses_32bit_layout_be :: proc(t: ^testing.T) {
	data := build_elf32_header_only(false, 0x08049000, 52, 12620, 0)
	defer delete(data)

	h, err := parse_header(data)
	testing.expect(t, err == "", "parse should succeed")

	testing.expect_value(t, h.entry, u64(0x08049000))
	testing.expect_value(t, h.phoff, u64(52))
	testing.expect_value(t, h.shoff, u64(12620))
	testing.expect_value(t, h.flags, u32(0))
	testing.expect_value(t, h.phentsize, u16(32))
	testing.expect_value(t, h.phnum, u16(9))
	testing.expect_value(t, h.shentsize, u16(40))
	testing.expect_value(t, h.shnum, u16(30))
	testing.expect_value(t, h.shstrndx, u16(29))
}

@(test)
test_regression_elf32_flags_not_contaminated :: proc(t: ^testing.T) {
	for little in ([2]bool{true, false}) {
		data := build_elf32_header_only(little, 0xdeadbeef, 0x11223344, 0x55667788, 0x05000402)
		defer delete(data)

		h, err := parse_header(data)
		testing.expect(t, err == "", "parse should succeed")

		testing.expect_value(t, h.entry, u64(0xdeadbeef))
		testing.expect_value(t, h.phoff, u64(0x11223344))
		testing.expect_value(t, h.shoff, u64(0x55667788))
		testing.expect_value(t, h.flags, u32(0x05000402))
	}
}

@(test)
test_regression_elf32_program_headers_parse :: proc(t: ^testing.T) {
	f := build_elf(ELF_CLASS_32, ELF_DATA_LSB)
	defer delete(f.data)

	info, err := load(f.data)
	testing.expect(t, err == "", "load should succeed")
	defer destroy(&info)

	testing.expect_value(t, info.header.phoff, u64(52))
	testing.expect_value(t, len(info.program_hdrs), 4)
	if len(info.program_hdrs) == 4 {
		testing.expect_value(t, info.program_hdrs[0].type, u32(PT_LOAD))
		testing.expect_value(t, info.program_hdrs[2].type, u32(PT_INTERP))
		testing.expect_value(t, info.program_hdrs[3].type, u32(PT_DYNAMIC))
	}
}

@(test)
test_in_bounds :: proc(t: ^testing.T) {
	data := make([]u8, 16)
	defer delete(data)

	testing.expect_value(t, in_bounds(data, 0, 16), true)
	testing.expect_value(t, in_bounds(data, 16, 0), true)
	testing.expect_value(t, in_bounds(data, 8, 8), true)
	testing.expect_value(t, in_bounds(data, 15, 1), true)

	testing.expect_value(t, in_bounds(data, 17, 0), false)
	testing.expect_value(t, in_bounds(data, 16, 1), false)
	testing.expect_value(t, in_bounds(data, 8, 9), false)
	testing.expect_value(t, in_bounds(data, 0, 17), false)
	testing.expect_value(t, in_bounds(data, 0, 0xFFFFFFFFFFFFFFFF), false)
	testing.expect_value(t, in_bounds(data, 0xFFFFFFFFFFFFFFFF, 0), false)
	testing.expect_value(t, in_bounds(data, 0xFFFFFFFFFFFFFFFF, 1), false)
	testing.expect_value(t, in_bounds(data, 0xFFFFFFFFFFFFFFF8, 8), false)
	testing.expect_value(t, in_bounds(data, 0xFF00000000000000, 0), false)
	testing.expect_value(t, in_bounds(data, 0x8000000000000000, 0), false)
}

@(test)
test_in_bounds_empty_slice :: proc(t: ^testing.T) {
	empty: []u8
	testing.expect_value(t, in_bounds(empty, 0, 0), true)
	testing.expect_value(t, in_bounds(empty, 0, 1), false)
	testing.expect_value(t, in_bounds(empty, 1, 0), false)
}

@(test)
test_getters_reject_negative_offsets :: proc(t: ^testing.T) {
	data := []u8{1, 2, 3, 4, 5, 6, 7, 8}

	for off in ([3]int{-1, -8, -1024}) {
		testing.expect_value(t, read_u16(data, off, .Little), u16(0))
		testing.expect_value(t, read_u32(data, off, .Little), u32(0))
		testing.expect_value(t, read_u64(data, off, .Little), u64(0))
		testing.expect_value(t, read_u16(data, off, .Big), u16(0))
		testing.expect_value(t, read_u32(data, off, .Big), u32(0))
		testing.expect_value(t, read_u64(data, off, .Big), u64(0))
	}
}

@(test)
test_getters_reject_past_end :: proc(t: ^testing.T) {
	data := []u8{1, 2, 3, 4, 5, 6, 7, 8}

	testing.expect_value(t, read_u16(data, 7, .Little), u16(0))
	testing.expect_value(t, read_u16(data, 8, .Little), u16(0))
	testing.expect_value(t, read_u16(data, 999, .Little), u16(0))
	testing.expect_value(t, read_u16(data, 7, .Big), u16(0))
	testing.expect_value(t, read_u16(data, 999, .Big), u16(0))

	testing.expect_value(t, read_u32(data, 5, .Little), u32(0))
	testing.expect_value(t, read_u32(data, 8, .Little), u32(0))
	testing.expect_value(t, read_u32(data, 5, .Big), u32(0))
	testing.expect_value(t, read_u32(data, 999, .Big), u32(0))

	testing.expect_value(t, read_u64(data, 1, .Little), u64(0))
	testing.expect_value(t, read_u64(data, 8, .Little), u64(0))
	testing.expect_value(t, read_u64(data, 1, .Big), u64(0))
	testing.expect_value(t, read_u64(data, 999, .Big), u64(0))
}

@(test)
test_getters_exact_fit :: proc(t: ^testing.T) {
	data := []u8{1, 2, 3, 4, 5, 6, 7, 8}

	testing.expect_value(t, read_u16(data, 6, .Little), u16(0x0807))
	testing.expect_value(t, read_u16(data, 6, .Big), u16(0x0708))
	testing.expect_value(t, read_u32(data, 4, .Little), u32(0x08070605))
	testing.expect_value(t, read_u32(data, 4, .Big), u32(0x05060708))
	testing.expect_value(t, read_u64(data, 0, .Little), u64(0x0807060504030201))
	testing.expect_value(t, read_u64(data, 0, .Big), u64(0x0102030405060708))
}

@(test)
test_getters_on_empty_slice :: proc(t: ^testing.T) {
	empty: []u8
	testing.expect_value(t, read_u16(empty, 0, .Little), u16(0))
	testing.expect_value(t, read_u32(empty, 0, .Little), u32(0))
	testing.expect_value(t, read_u64(empty, 0, .Little), u64(0))
	testing.expect_value(t, read_u16(empty, 0, .Big), u16(0))
	testing.expect_value(t, read_u32(empty, 0, .Big), u32(0))
	testing.expect_value(t, read_u64(empty, 0, .Big), u64(0))
}

build_elf64_with_segments :: proc(segs: []Program_Header) -> []u8 {
	ehsize := 64
	total := ehsize + len(segs) * 56
	data := make([]u8, total)

	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = ELF_CLASS_64
	data[5] = ELF_DATA_LSB
	data[6] = 1

	put_u16(data, 16, ET_DYN, true)
	put_u16(data, 18, EM_X86_64, true)
	put_u64(data, 32, u64(ehsize), true)
	put_u16(data, 52, u16(ehsize), true)
	put_u16(data, 54, 56, true)
	put_u16(data, 56, u16(len(segs)), true)
	put_u16(data, 58, 64, true)

	for seg, i in segs {
		write_phdr(data, ehsize + i * 56, true, true, seg)
	}
	return data
}

@(test)
test_is_dynamic_with_pt_dynamic_and_no_interp :: proc(t: ^testing.T) {
	segs := [2]Program_Header{
		{type = PT_LOAD, offset = 0, filesz = 0x100, memsz = 0x100},
		{type = PT_DYNAMIC, offset = 0x2000, filesz = 0xe0, memsz = 0xe0},
	}
	data := build_elf64_with_segments(segs[:])
	defer delete(data)

	info, err := load(data)
	testing.expect(t, err == "", "load should succeed")
	defer destroy(&info)

	testing.expect_value(t, info.is_dynamic, true)
	testing.expect_value(t, info.interp_offset, u64(0))
	testing.expect_value(t, info.is_pie, true)
}

@(test)
test_is_dynamic_with_interp_only :: proc(t: ^testing.T) {
	segs := [2]Program_Header{
		{type = PT_LOAD, offset = 0, filesz = 0x100, memsz = 0x100},
		{type = PT_INTERP, offset = 0x318, filesz = 0x1c, memsz = 0x1c},
	}
	data := build_elf64_with_segments(segs[:])
	defer delete(data)

	info, err := load(data)
	testing.expect(t, err == "", "load should succeed")
	defer destroy(&info)

	testing.expect_value(t, info.is_dynamic, true)
	testing.expect_value(t, info.interp_offset, u64(0x318))
}

@(test)
test_is_dynamic_false_for_static :: proc(t: ^testing.T) {
	segs := [2]Program_Header{
		{type = PT_LOAD, offset = 0, filesz = 0x100, memsz = 0x100},
		{type = PT_GNU_STACK, offset = 0, filesz = 0, memsz = 0},
	}
	data := build_elf64_with_segments(segs[:])
	defer delete(data)

	info, err := load(data)
	testing.expect(t, err == "", "load should succeed")
	defer destroy(&info)

	testing.expect_value(t, info.is_dynamic, false)
	testing.expect_value(t, info.interp_offset, u64(0))
}

@(test)
test_load_destroy_leaks_nothing :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	{
		context.allocator = mem.tracking_allocator(&track)

		classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}
		endians := [2]u8{ELF_DATA_LSB, ELF_DATA_MSB}
		for class in classes {
			for endian in endians {
				f := build_elf(class, endian)
				info, err := load(f.data)
				testing.expect(t, err == "", "load should succeed")
				testing.expect(t, len(info.symbols) > 0, "fixture should carry symbols")
				destroy(&info)
				delete(f.data)
			}
		}
	}

	testing.expect_value(t, len(track.allocation_map), 0)
	testing.expect_value(t, len(track.bad_free_array), 0)
}

POISON :: [7]u64{
	0xFF00000000000000,
	0x8000000000000000,
	0xFFFFFFFFFFFFFFFF,
	0x7FFFFFFFFFFFFFFF,
	0x00000000FFFFFFFF,
	0x0000000080000000,
	0xFFFFFFFFFFFFFFF0,
}

// Every string the parser hands back must alias the caller's buffer.
inside :: proc(ptr: rawptr, size: int, data: []u8) -> bool {
	if size == 0 { return true }
	if size < 0 { return false }
	lo := uintptr(raw_data(data))
	p  := uintptr(ptr)
	return p >= lo && p - lo <= uintptr(len(data)) && uintptr(len(data)) - (p - lo) >= uintptr(size)
}

expect_sane_load :: proc(t: ^testing.T, data: []u8, label: string) {
	info, err := load(data)
	if err != "" { return }
	defer destroy(&info)

	phentsize := 56 if info.is_64bit else 32
	shentsize := 64 if info.is_64bit else 40

	// e_phnum == PN_XNUM and e_shnum == 0 are escape hatches; the real counts
	// come from section[0], so the header field is not an upper bound there.
	if info.header.phnum != PN_XNUM {
		testing.expect(t, len(info.program_hdrs) <= int(info.header.phnum), label)
	}
	if info.header.shnum != 0 {
		testing.expect(t, len(info.section_hdrs) <= int(info.header.shnum), label)
	}
	testing.expect(t, len(info.program_hdrs) * phentsize <= len(data), label)
	testing.expect(t, len(info.section_hdrs) * shentsize <= len(data), label)

	testing.expect(t, inside(raw_data(info.shstrtab), len(info.shstrtab), data), label)
	testing.expect(t, inside(raw_data(info.strtab), len(info.strtab), data), label)
	testing.expect(t, inside(raw_data(info.dynstr), len(info.dynstr), data), label)

	for shdr in info.section_hdrs {
		name := get_section_name(&info, shdr)
		if name == "<unknown>" { continue }
		testing.expect(t, inside(raw_data(name), len(name), data), label)
	}
	for sym in info.symbols {
		testing.expect(t, inside(raw_data(sym.name), len(sym.name), data), label)
	}
	for sym in info.dyn_symbols {
		testing.expect(t, inside(raw_data(sym.name), len(sym.name), data), label)
	}
}

poison_header_offsets :: proc(f: Fixture, v: u64) {
	little := f.endian == ELF_DATA_LSB
	if f.class == ELF_CLASS_64 {
		put_u64(f.data, 32, v, little)
		put_u64(f.data, 40, v, little)
	} else {
		put_u32(f.data, 28, u32(v), little)
		put_u32(f.data, 32, u32(v), little)
	}
}

@(test)
test_malformed_poisoned_phoff_shoff :: proc(t: ^testing.T) {
	classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}
	endians := [2]u8{ELF_DATA_LSB, ELF_DATA_MSB}
	poisons := POISON

	for class in classes {
		for endian in endians {
			for p in poisons {
				f := build_elf(class, endian)
				poison_header_offsets(f, p)
				expect_sane_load(t, f.data, "poisoned phoff/shoff")
				delete(f.data)
			}

			f := build_elf(class, endian)
			poison_header_offsets(f, u64(len(f.data)) + 1)
			expect_sane_load(t, f.data, "phoff/shoff just past end")
			delete(f.data)

			g := build_elf(class, endian)
			poison_header_offsets(g, u64(len(g.data)))
			expect_sane_load(t, g.data, "phoff/shoff exactly at end")
			delete(g.data)
		}
	}
}

@(test)
test_malformed_saturated_counts :: proc(t: ^testing.T) {
	classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}
	endians := [2]u8{ELF_DATA_LSB, ELF_DATA_MSB}

	for class in classes {
		for endian in endians {
			f := build_elf(class, endian)
			little := endian == ELF_DATA_LSB
			if class == ELF_CLASS_64 {
				put_u16(f.data, 56, 0xFFFF, little)
				put_u16(f.data, 60, 0xFFFF, little)
				put_u16(f.data, 62, 0xFFFF, little)
			} else {
				put_u16(f.data, 44, 0xFFFF, little)
				put_u16(f.data, 48, 0xFFFF, little)
				put_u16(f.data, 50, 0xFFFF, little)
			}
			expect_sane_load(t, f.data, "saturated phnum/shnum/shstrndx")
			delete(f.data)
		}
	}
}

@(test)
test_malformed_saturated_entsizes :: proc(t: ^testing.T) {
	classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}

	for class in classes {
		f := build_elf(class, ELF_DATA_LSB)
		if class == ELF_CLASS_64 {
			put_u16(f.data, 54, 0xFFFF, true)
			put_u16(f.data, 58, 0xFFFF, true)
		} else {
			put_u16(f.data, 42, 0xFFFF, true)
			put_u16(f.data, 46, 0xFFFF, true)
		}
		expect_sane_load(t, f.data, "saturated phentsize/shentsize")
		delete(f.data)
	}
}

@(test)
test_malformed_poisoned_section_offsets :: proc(t: ^testing.T) {
	classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}
	endians := [2]u8{ELF_DATA_LSB, ELF_DATA_MSB}
	poisons := POISON

	for class in classes {
		for endian in endians {
			for p in poisons {
				f := build_elf(class, endian)
				little := endian == ELF_DATA_LSB
				for i in 0 ..< int(f.shnum) {
					base := int(f.shoff) + i * int(f.shentsize)
					if class == ELF_CLASS_64 {
						put_u64(f.data, base+24, p, little)
						put_u64(f.data, base+32, p, little)
					} else {
						put_u32(f.data, base+16, u32(p), little)
						put_u32(f.data, base+20, u32(p), little)
					}
				}
				expect_sane_load(t, f.data, "poisoned sh_offset/sh_size")
				delete(f.data)
			}
		}
	}
}

// offset + size wraps past 2^64, which a naive `offset + size <= len` check accepts.
@(test)
test_malformed_section_offset_size_wraps :: proc(t: ^testing.T) {
	pairs := [5][2]u64{
		{0xFFFFFFFFFFFFFFF0, 0x10},
		{0xFFFFFFFFFFFFFF00, 0x100},
		{0xFFFFFFFFFFFFFFFF, 1},
		{0x8000000000000000, 0x8000000000000000},
		{8, 0xFFFFFFFFFFFFFFF8},
	}
	targets := [4]int{SEC_SYMTAB, SEC_STRTAB, SEC_DYNSYM, SEC_SHSTRTAB}

	for pair in pairs {
		for target in targets {
			f := build_elf(ELF_CLASS_64, ELF_DATA_LSB)
			base := int(f.shoff) + target * int(f.shentsize)
			put_u64(f.data, base+24, pair[0], true)
			put_u64(f.data, base+32, pair[1], true)
			expect_sane_load(t, f.data, "sh_offset + sh_size wraps around u64")
			delete(f.data)
		}
	}
}

@(test)
test_malformed_poisoned_section_names :: proc(t: ^testing.T) {
	classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}
	names := [4]u32{0xFFFFFFFF, 0x80000000, u32(len(SHSTRTAB_BLOB)), u32(len(SHSTRTAB_BLOB)) - 1}

	for class in classes {
		for n in names {
			f := build_elf(class, ELF_DATA_LSB)
			for i in 0 ..< int(f.shnum) {
				put_u32(f.data, int(f.shoff) + i * int(f.shentsize), n, true)
			}
			expect_sane_load(t, f.data, "poisoned sh_name")
			delete(f.data)
		}
	}
}

@(test)
test_malformed_symtab_link_out_of_range :: proc(t: ^testing.T) {
	classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}
	links := [4]u32{0xFFFFFFFF, 0x7FFFFFFF, 8, 0}

	for class in classes {
		for link in links {
			f := build_elf(class, ELF_DATA_LSB)
			link_off := 40 if class == ELF_CLASS_64 else 24
			base := int(f.shoff) + SEC_SYMTAB * int(f.shentsize)
			put_u32(f.data, base + link_off, link, true)

			info, err := load(f.data)
			testing.expect(t, err == "", "load should succeed")

			if link >= u32(f.shnum) {
				testing.expect_value(t, len(info.symbols), 0)
			}
			for sym in info.symbols {
				testing.expect(t, len(sym.name) <= len(info.strtab), "symbol name must stay inside strtab")
			}
			destroy(&info)
			delete(f.data)
		}
	}
}

@(test)
test_malformed_truncated_images :: proc(t: ^testing.T) {
	classes := [2]u8{ELF_CLASS_32, ELF_CLASS_64}
	endians := [2]u8{ELF_DATA_LSB, ELF_DATA_MSB}

	for class in classes {
		for endian in endians {
			f := build_elf(class, endian)
			for n in 0 ..= len(f.data) {
				expect_sane_load(t, f.data[:n], "truncated image")
			}
			delete(f.data)
		}
	}
}

@(test)
test_malformed_header_byte_sweep :: proc(t: ^testing.T) {
	patterns := [4]u8{0x00, 0x01, 0x7f, 0xff}

	for pat in patterns {
		for i in 0 ..< 64 {
			f := build_elf(ELF_CLASS_64, ELF_DATA_LSB)
			f.data[i] = pat
			expect_sane_load(t, f.data, "single byte flip in ELF64 header")
			delete(f.data)

			g := build_elf(ELF_CLASS_32, ELF_DATA_MSB)
			if i < len(g.data) {
				g.data[i] = pat
			}
			expect_sane_load(t, g.data, "single byte flip in ELF32 header")
			delete(g.data)
		}
	}
}

@(test)
test_parse_header_unknown_class :: proc(t: ^testing.T) {
	data := make([]u8, 64)
	defer delete(data)
	make_elf64_header(data, ET_EXEC, EM_X86_64)
	data[4] = 7

	_, err := parse_header(data)
	testing.expect(t, err != "", "unknown class must be rejected")

	info, load_err := load(data)
	testing.expect(t, load_err != "", "load must propagate the class error")
	testing.expect_value(t, len(info.program_hdrs), 0)
}

@(test)
test_load_rejects_non_elf :: proc(t: ^testing.T) {
	data := []u8{'M', 'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := load(data)
	testing.expect(t, err != "", "non-ELF data must be rejected")
}

@(test)
test_get_section_name_without_shstrtab :: proc(t: ^testing.T) {
	info: ELF_Info
	shdr := Section_Header{name = 4}
	testing.expect_value(t, get_section_name(&info, shdr), "<unknown>")

	empty: []u8
	info.shstrtab = empty
	testing.expect_value(t, get_section_name(&info, shdr), "<unknown>")
}

@(test)
test_get_symbol_name_bounds :: proc(t: ^testing.T) {
	strtab := transmute([]u8)string(STRTAB_BLOB)

	testing.expect_value(t, get_symbol_name(strtab, STR_MAIN), "main")
	testing.expect_value(t, get_symbol_name(strtab, STR_COUNTER), "counter")
	testing.expect_value(t, get_symbol_name(strtab, STR_PRINTF), "printf")
	testing.expect_value(t, get_symbol_name(strtab, 0), "")
	testing.expect_value(t, get_symbol_name(strtab, u32(len(STRTAB_BLOB))), "")
	testing.expect_value(t, get_symbol_name(strtab, 0xFFFFFFFF), "")

	unterminated := []u8{'a', 'b', 'c'}
	testing.expect_value(t, get_symbol_name(unterminated, 0), "")

	empty: []u8
	testing.expect_value(t, get_symbol_name(empty, 0), "")
	testing.expect_value(t, get_symbol_name(nil, 5), "")
}

@(test)
test_printer_strings :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)

	testing.expect_value(t, type_to_str(ET_REL), "REL (Relocatable)")
	testing.expect_value(t, type_to_str(ET_EXEC), "EXEC (Executable)")
	testing.expect_value(t, type_to_str(ET_DYN), "DYN (Shared Object/PIE)")
	testing.expect_value(t, type_to_str(ET_CORE), "CORE")
	testing.expect_value(t, type_to_str(999), "UNKNOWN (999)")

	testing.expect_value(t, machine_to_str(EM_386), "x86 (i386)")
	testing.expect_value(t, machine_to_str(EM_X86_64), "x86-64")
	testing.expect_value(t, machine_to_str(EM_ARM), "ARM")
	testing.expect_value(t, machine_to_str(EM_AARCH64), "AArch64")
	testing.expect_value(t, machine_to_str(EM_RISCV), "RISC-V")
	testing.expect_value(t, machine_to_str(1234), "Unknown (1234)")

	testing.expect_value(t, section_type_str(SHT_NULL), "NULL")
	testing.expect_value(t, section_type_str(SHT_PROGBITS), "PROGBITS")
	testing.expect_value(t, section_type_str(SHT_SYMTAB), "SYMTAB")
	testing.expect_value(t, section_type_str(SHT_STRTAB), "STRTAB")
	testing.expect_value(t, section_type_str(SHT_DYNSYM), "DYNSYM")
	testing.expect_value(t, section_type_str(0x6ffffff6), "GNU_HASH")
	testing.expect_value(t, section_type_str(0x1234), "0x1234")

	testing.expect_value(t, symbol_type_str(STT_NOTYPE), "NOTYPE")
	testing.expect_value(t, symbol_type_str(STT_OBJECT), "OBJECT")
	testing.expect_value(t, symbol_type_str(STT_FUNC), "FUNC")
	testing.expect_value(t, symbol_type_str(STT_SECTION), "SECTION")
	testing.expect_value(t, symbol_type_str(STT_FILE), "FILE")
	testing.expect_value(t, symbol_type_str(13), "0xd")

	testing.expect_value(t, symbol_bind_str(STB_LOCAL), "LOCAL")
	testing.expect_value(t, symbol_bind_str(STB_GLOBAL), "GLOBAL")
	testing.expect_value(t, symbol_bind_str(STB_WEAK), "WEAK")
	testing.expect_value(t, symbol_bind_str(10), "0xa")

	testing.expect_value(t, segment_type_str(PT_NULL), "NULL")
	testing.expect_value(t, segment_type_str(PT_LOAD), "LOAD")
	testing.expect_value(t, segment_type_str(PT_DYNAMIC), "DYNAMIC")
	testing.expect_value(t, segment_type_str(PT_INTERP), "INTERP")
	testing.expect_value(t, segment_type_str(PT_GNU_RELRO), "GNU_RELRO")
	testing.expect_value(t, segment_type_str(0xabc), "0xabc")
}

@(test)
test_flags_to_str :: proc(t: ^testing.T) {
	testing.expect_value(t, flags_to_str(0), "   ")
	testing.expect_value(t, flags_to_str(PF_X), "  X")
	testing.expect_value(t, flags_to_str(PF_W), " W ")
	testing.expect_value(t, flags_to_str(PF_R), "R  ")
	testing.expect_value(t, flags_to_str(PF_R | PF_X), "R X")
	testing.expect_value(t, flags_to_str(PF_R | PF_W), "RW ")
	testing.expect_value(t, flags_to_str(PF_R | PF_W | PF_X), "RWX")
	testing.expect_value(t, flags_to_str(0xFFFFFFFFFFFFFFFF), "RWX")
}
