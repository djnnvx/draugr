package analysis

import "core:c"
import "core:encoding/endian"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/linux"
import "core:sys/posix"

import "../elf"

foreign import libc "system:c"

@(default_calling_convention="c")
foreign libc {
	system :: proc(command: cstring) -> c.int ---
	dlinfo :: proc(handle: rawptr, request: c.int, info: rawptr) -> c.int ---
}

Link_Map :: struct {
	l_addr : uintptr,
}

RTLD_DI_LINKMAP :: 2

Callee :: #type proc "c" (u64, u64, u64, u64, u64, u64) -> u64

Patch_Kind :: enum { Ret, Jmp, Got }

Patch :: struct {
	kind   : Patch_Kind,
	target : string,
	value  : u64,
	repl   : string,
}

// The callee runs in a forked child so a crash is a report, not a dead draugr.
call_function :: proc(data: []u8, info: ^elf.ELF_Info, path: string, symbol: string, raw_args: string, raw_patch: string) -> string {
	args, parse_err := parse_call_args(raw_args)
	defer delete(args)
	if parse_err != "" {
		return parse_err
	}

	patches, patch_err := parse_patches(raw_patch)
	defer delete(patches)
	if patch_err != "" {
		return patch_err
	}
	if len(patches) > 0 && info.header.machine != elf.EM_X86_64 {
		return "patching only supported on x86-64"
	}

	fd, err := linux.memfd_create("draugr-call", {})
	if err != .NONE {
		return fmt.tprintf("memfd_create failed: %v", err)
	}
	defer linux.close(fd)

	fd_path := fmt.tprintf("/proc/self/fd/%d", int(fd))

	if info.header.type == elf.ET_REL {
		cmd := fmt.ctprintf("ld -shared -o %s %s", fd_path, path)
		if system(cmd) != 0 {
			return fmt.tprintf("failed to link %s into a shared object", path)
		}
	} else {
		if _, werr := linux.write(fd, data); werr != .NONE {
			return fmt.tprintf("writing to memfd failed: %v", werr)
		}
	}

	fmt.fprintf(os.stderr, "calling %s in a forked child, loaded from memory\n", symbol)

	pid, ferr := linux.fork()
	if ferr != .NONE {
		return fmt.tprintf("fork failed: %v", ferr)
	}

	if pid == 0 {
		run_callee(fd_path, symbol, args, info, patches)
	}

	status: u32
	if _, werr := linux.waitpid(pid, &status, {}, nil); werr != .NONE {
		return fmt.tprintf("waitpid failed: %v", werr)
	}
	return report_status(status)
}

run_callee :: proc(fd_path: string, symbol: string, args: []u64, info: ^elf.ELF_Info, patches: []Patch) -> ! {
	handle := posix.dlopen(strings.clone_to_cstring(fd_path, context.temp_allocator), {.NOW})
	if handle == nil {
		fmt.fprintf(os.stderr, "dlopen: %s\n", posix.dlerror())
		linux.exit(101)
	}

	for p in patches {
		if perr := apply_patch(handle, info, p); perr != "" {
			fmt.fprintf(os.stderr, "patch: %s\n", perr)
			linux.exit(103)
		}
	}

	sym := posix.dlsym(handle, strings.clone_to_cstring(symbol, context.temp_allocator))
	if sym == nil {
		fmt.fprintf(os.stderr, "dlsym: %s\n", posix.dlerror())
		linux.exit(102)
	}

	fn := cast(Callee)sym
	result := fn(args[0], args[1], args[2], args[3], args[4], args[5])

	fmt.printf("%s returned %d (0x%x)\n", symbol, i64(result), result)
	os.flush(os.stdout)
	linux.exit(0)
}

report_status :: proc(status: u32) -> string {
	if status & 0x7f == 0 {
		code := (status >> 8) & 0xff
		switch code {
		case 0:   return ""
		case 101: return "dlopen failed, see above"
		case 102: return "symbol not found, see above"
		case 103: return "patch failed, see above"
		}
		return fmt.tprintf("callee exited with status %d", code)
	}
	return fmt.tprintf("callee died on signal %d", status & 0x7f)
}

apply_patch :: proc(handle: posix.Symbol_Table, info: ^elf.ELF_Info, p: Patch) -> string {
	switch p.kind {
	case .Ret:
		fn := sym_addr(handle, p.target)
		if fn == nil {
			return fmt.tprintf("symbol not found: %s", p.target)
		}
		code := [11]u8{0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3}
		if werr := fits(info, p.target, len(code)); werr != "" {
			return werr
		}
		endian.unchecked_put_u64le(code[2:10], p.value)
		return write_code(fn, code[:])

	case .Jmp:
		fn := sym_addr(handle, p.target)
		if fn == nil {
			return fmt.tprintf("symbol not found: %s", p.target)
		}
		to := sym_addr(handle, p.repl)
		if to == nil {
			return fmt.tprintf("symbol not found: %s", p.repl)
		}
		code := [12]u8{0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0}
		if werr := fits(info, p.target, len(code)); werr != "" {
			return werr
		}
		endian.unchecked_put_u64le(code[2:10], u64(uintptr(to)))
		return write_code(fn, code[:])

	case .Got:
		to := sym_addr(handle, p.repl)
		if to == nil {
			return fmt.tprintf("symbol not found: %s", p.repl)
		}
		slot := got_slot(handle, info, p.target)
		if slot == nil {
			return fmt.tprintf("no GOT slot for import: %s", p.target)
		}
		if werr := make_writable(slot, 8); werr != "" {
			return werr
		}
		(^rawptr)(slot)^ = to
		return ""
	}
	return ""
}

sym_addr :: proc(handle: posix.Symbol_Table, name: string) -> rawptr {
	return posix.dlsym(handle, strings.clone_to_cstring(name, context.temp_allocator))
}

got_slot :: proc(handle: posix.Symbol_Table, info: ^elf.ELF_Info, import_name: string) -> rawptr {
	lm: ^Link_Map
	if dlinfo(rawptr(handle), RTLD_DI_LINKMAP, &lm) != 0 || lm == nil {
		return nil
	}
	for r in info.relocs {
		if r.sym_name == import_name && (r.type == 6 || r.type == 7) {
			return rawptr(lm.l_addr + uintptr(r.offset))
		}
	}
	return nil
}

fits :: proc(info: ^elf.ELF_Info, name: string, need: int) -> string {
	size := u64(0)
	for s in info.symbols {
		if s.name == name && s.size != 0 { size = s.size; break }
	}
	if size == 0 {
		for s in info.dyn_symbols {
			if s.name == name && s.size != 0 { size = s.size; break }
		}
	}
	if size != 0 && size < u64(need) {
		return fmt.tprintf("%s is %d bytes, too small for a %d-byte patch", name, size, need)
	}
	return ""
}

write_code :: proc(dst: rawptr, code: []u8) -> string {
	if werr := make_writable(dst, len(code)); werr != "" {
		return werr
	}
	mem.copy(dst, raw_data(code), len(code))
	return ""
}

make_writable :: proc(ptr: rawptr, length: int) -> string {
	page := uintptr(4096)
	start := uintptr(ptr) & ~(page - 1)
	end := (uintptr(ptr) + uintptr(length) + page - 1) & ~(page - 1)
	if err := linux.mprotect(rawptr(start), uint(end - start), {.READ, .WRITE, .EXEC}); err != .NONE {
		return fmt.tprintf("mprotect failed: %v", err)
	}
	return ""
}

parse_patches :: proc(raw: string) -> ([]Patch, string) {
	if raw == "" {
		return nil, ""
	}

	specs := strings.split(raw, ";", context.temp_allocator)
	patches := make([]Patch, len(specs))
	n := 0

	for spec in specs {
		s := strings.trim_space(spec)
		if s == "" {
			continue
		}

		eq := strings.index_byte(s, '=')
		if eq < 0 {
			return patches[:n], fmt.tprintf("patch spec missing '=': %s", s)
		}
		lhs := strings.trim_space(s[:eq])
		rhs := strings.trim_space(s[eq + 1:])

		p: Patch
		switch {
		case strings.has_prefix(lhs, "got:"):
			p.kind = .Got
			p.target = strings.trim_space(lhs[4:])
			p.repl = rhs
			if p.target == "" || p.repl == "" {
				return patches[:n], fmt.tprintf("got: patch needs got:import=target: %s", s)
			}
		case strings.has_prefix(rhs, "ret:"):
			p.kind = .Ret
			p.target = lhs
			v, ok := strconv.parse_i64_maybe_prefixed(strings.trim_space(rhs[4:]))
			if !ok {
				return patches[:n], fmt.tprintf("ret: patch needs an integer: %s", s)
			}
			p.value = u64(v)
		case strings.has_prefix(rhs, "jmp:"):
			p.kind = .Jmp
			p.target = lhs
			p.repl = strings.trim_space(rhs[4:])
			if p.repl == "" {
				return patches[:n], fmt.tprintf("jmp: patch needs a target symbol: %s", s)
			}
		case:
			return patches[:n], fmt.tprintf("unknown patch spec: %s", s)
		}

		if p.target == "" {
			return patches[:n], fmt.tprintf("patch spec missing symbol: %s", s)
		}

		patches[n] = p
		n += 1
	}

	return patches[:n], ""
}

parse_call_args :: proc(raw: string) -> ([]u64, string) {
	args := make([]u64, 6)
	if raw == "" {
		return args, ""
	}

	fields := strings.split(raw, ",", context.temp_allocator)
	if len(fields) > 6 {
		return args, "at most 6 arguments are supported"
	}

	for field, i in fields {
		f := strings.trim_space(field)
		if strings.has_prefix(f, "s:") {
			args[i] = u64(uintptr(rawptr(strings.clone_to_cstring(f[2:]))))
			continue
		}
		v, ok := strconv.parse_i64_maybe_prefixed(f)
		if !ok {
			return args, fmt.tprintf("argument %d is not an integer or s:string: %s", i, f)
		}
		args[i] = u64(v)
	}
	return args, ""
}
