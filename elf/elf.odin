package elf

import "core:encoding/endian"
import "core:fmt"

ELF_MAGIC :: [4]u8{0x7f, 'E', 'L', 'F'}

ELF_CLASS_32 :: 1
ELF_CLASS_64 :: 2

ELF_DATA_LSB :: 1
ELF_DATA_MSB :: 2

ET_REL  :: 1
ET_EXEC :: 2
ET_DYN  :: 3
ET_CORE :: 4

EM_SPARC        :: 2
EM_386          :: 3
EM_68K          :: 4
EM_MIPS         :: 8
EM_MIPS_RS3_LE  :: 10
EM_PARISC       :: 15
EM_PPC          :: 20
EM_PPC64        :: 21
EM_S390         :: 22
EM_ARM          :: 40
EM_SH           :: 42
EM_SPARCV9      :: 43
EM_ARC          :: 45
EM_IA_64        :: 50
EM_X86_64       :: 62
EM_CRIS         :: 76
EM_AVR          :: 83
EM_FR30         :: 84
EM_V850         :: 87
EM_M32R         :: 88
EM_OPENRISC     :: 92
EM_ARC_COMPACT  :: 93
EM_XTENSA       :: 94
EM_MSP430       :: 105
EM_BLACKFIN     :: 106
EM_UNICORE      :: 110
EM_TI_C6000     :: 140
EM_NDS32        :: 167
EM_AARCH64      :: 183
EM_MICROBLAZE   :: 189
EM_TILEGX       :: 191
EM_ARC_COMPACT2 :: 195
EM_RISCV        :: 243
EM_BPF          :: 247
EM_CSKY         :: 252
EM_LOONGARCH    :: 258

PT_NULL    :: 0
PT_LOAD    :: 1
PT_DYNAMIC :: 2
PT_INTERP  :: 3
PT_NOTE    :: 4
PT_SHLIB   :: 5
PT_PHDR    :: 6
PT_TLS     :: 7
PT_GNU_EH_FRAME :: 0x6474e550
PT_GNU_STACK    :: 0x6474e551
PT_GNU_RELRO    :: 0x6474e552

PF_X :: 1
PF_W :: 2
PF_R :: 4

SHF_EXECINSTR :: 4

SHT_NULL     :: 0
SHT_PROGBITS :: 1
SHT_SYMTAB   :: 2
SHT_STRTAB   :: 3
SHT_RELA     :: 4
SHT_HASH     :: 5
SHT_DYNAMIC  :: 6
SHT_NOTE     :: 7
SHT_NOBITS   :: 8
SHT_REL      :: 9
SHT_SHLIB    :: 10
SHT_DYNSYM   :: 11
SHT_INIT_ARRAY    :: 14
SHT_FINI_ARRAY    :: 15
SHT_PREINIT_ARRAY :: 16
SHT_GROUP         :: 17
SHT_SYMTAB_SHNDX  :: 18
SHT_GNU_ATTRIBUTES :: 0x6ffffff5
SHT_GNU_HASH       :: 0x6ffffff6
SHT_GNU_VERDEF     :: 0x6ffffffd
SHT_GNU_VERNEED    :: 0x6ffffffe
SHT_GNU_VERSYM     :: 0x6fffffff

SHN_UNDEF  :: 0
SHN_XINDEX :: 0xFFFF
PN_XNUM    :: 0xFFFF

STB_LOCAL  :: 0
STB_GLOBAL :: 1
STB_WEAK   :: 2

STT_NOTYPE  :: 0
STT_OBJECT  :: 1
STT_FUNC    :: 2
STT_SECTION :: 3
STT_FILE    :: 4

ELF_Header :: struct {
	class        : u8,
	data         : u8,
	osabi        : u8,
	type         : u16,
	machine      : u16,
	entry        : u64,
	phoff        : u64,
	shoff        : u64,
	phentsize    : u16,
	phnum        : u16,
	shentsize    : u16,
	shnum        : u16,
	shstrndx     : u16,
	flags        : u32,
}

Program_Header :: struct {
	type    : u32,
	flags   : u64,
	offset  : u64,
	vaddr   : u64,
	paddr   : u64,
	filesz  : u64,
	memsz   : u64,
	align   : u64,
}

Section_Header :: struct {
	name      : u32,
	type      : u32,
	flags     : u64,
	addr      : u64,
	offset    : u64,
	size      : u64,
	link      : u32,
	info      : u32,
	addralign : u64,
	entsize   : u64,
}

Symbol :: struct {
	name  : string,
	value : u64,
	size  : u64,
	bind  : u8,
	type  : u8,
	shndx : u16,
}

ELF_Info :: struct {
	header        : ELF_Header,
	program_hdrs  : [dynamic]Program_Header,
	section_hdrs  : [dynamic]Section_Header,
	symbols       : [dynamic]Symbol,
	dyn_symbols   : [dynamic]Symbol,
	is_64bit      : bool,
	is_pie        : bool,
	is_dynamic    : bool,
	interp_offset : u64,
	shstrtab      : []u8,
	strtab        : []u8,
	dynstr        : []u8,
}

// Overflow-safe: no addition that can wrap.
in_bounds :: proc(data: []u8, offset: u64, size: u64) -> bool {
	return offset <= u64(len(data)) && size <= u64(len(data)) - offset
}

Byte_Order :: endian.Byte_Order

byte_order :: proc(header: ELF_Header) -> Byte_Order {
	return .Little if header.data == ELF_DATA_LSB else .Big
}

// Out-of-range reads yield 0 rather than faulting; ELF fields are untrusted.
read_u16 :: proc(data: []u8, offset: int, order: Byte_Order) -> u16 {
	if offset < 0 || offset + 2 > len(data) { return 0 }
	v, _ := endian.get_u16(data[offset:offset + 2], order)
	return v
}

read_u32 :: proc(data: []u8, offset: int, order: Byte_Order) -> u32 {
	if offset < 0 || offset + 4 > len(data) { return 0 }
	v, _ := endian.get_u32(data[offset:offset + 4], order)
	return v
}

read_u64 :: proc(data: []u8, offset: int, order: Byte_Order) -> u64 {
	if offset < 0 || offset + 8 > len(data) { return 0 }
	v, _ := endian.get_u64(data[offset:offset + 8], order)
	return v
}

probe :: proc(data: []u8) -> bool {
	if len(data) < 16 { return false }
	if data[0] != ELF_MAGIC[0] { return false }
	if data[1] != ELF_MAGIC[1] { return false }
	if data[2] != ELF_MAGIC[2] { return false }
	if data[3] != ELF_MAGIC[3] { return false }
	return true
}

parse_header :: proc(data: []u8) -> (ELF_Header, string) {
	header: ELF_Header
	
	if len(data) < 16 {
		return header, "Data too small"
	}
	
	if !probe(data) {
		return header, "Invalid ELF magic"
	}
	
	header.class = data[4]
	header.data = data[5]
	header.osabi = data[7]
	
	is_64bit := header.class == ELF_CLASS_64
	order := byte_order(header)

	if !is_64bit {
		if header.class != ELF_CLASS_32 {
			return header, fmt.tprintf("Unknown ELF class: %d", header.class)
		}
	}

	header.type = read_u16(data, 16, order)
	header.machine = read_u16(data, 18, order)

	if is_64bit {
		header.entry = read_u64(data, 24, order)
		header.phoff = read_u64(data, 32, order)
		header.shoff = read_u64(data, 40, order)
		header.flags = read_u32(data, 48, order)
		header.phentsize = read_u16(data, 54, order)
		header.phnum = read_u16(data, 56, order)
		header.shentsize = read_u16(data, 58, order)
		header.shnum = read_u16(data, 60, order)
		header.shstrndx = read_u16(data, 62, order)
	} else {
		header.entry = u64(read_u32(data, 24, order))
		header.phoff = u64(read_u32(data, 28, order))
		header.shoff = u64(read_u32(data, 32, order))
		header.flags = read_u32(data, 36, order)
		header.phentsize = read_u16(data, 42, order)
		header.phnum = read_u16(data, 44, order)
		header.shentsize = read_u16(data, 46, order)
		header.shnum = read_u16(data, 48, order)
		header.shstrndx = read_u16(data, 50, order)
	}

	return header, ""
}
