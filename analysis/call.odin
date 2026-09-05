package analysis

import "core:c"
import "core:fmt"
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
}

Callee :: #type proc "c" (u64, u64, u64, u64, u64, u64) -> u64

// The callee runs in a forked child so a crash is a report, not a dead draugr.
call_function :: proc(data: []u8, info: ^elf.ELF_Info, path: string, symbol: string, raw_args: string) -> string {
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

	args, parse_err := parse_call_args(raw_args)
	defer delete(args)
	if parse_err != "" {
		return parse_err
	}

	fmt.fprintf(os.stderr, "calling %s in a forked child, loaded from memory\n", symbol)

	pid, ferr := linux.fork()
	if ferr != .NONE {
		return fmt.tprintf("fork failed: %v", ferr)
	}

	if pid == 0 {
		run_callee(fd_path, symbol, args)
	}

	status: u32
	if _, werr := linux.waitpid(pid, &status, {}, nil); werr != .NONE {
		return fmt.tprintf("waitpid failed: %v", werr)
	}
	return report_status(status)
}

run_callee :: proc(fd_path: string, symbol: string, args: []u64) -> ! {
	handle := posix.dlopen(strings.clone_to_cstring(fd_path, context.temp_allocator), {.NOW})
	if handle == nil {
		fmt.fprintf(os.stderr, "dlopen: %s\n", posix.dlerror())
		linux.exit(101)
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
		}
		return fmt.tprintf("callee exited with status %d", code)
	}
	return fmt.tprintf("callee died on signal %d", status & 0x7f)
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
