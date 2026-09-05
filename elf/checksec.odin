package elf

import "core:strings"

Relro :: enum { None, Partial, Full }
Nx    :: enum { Unknown, Enabled, Disabled }
Pie   :: enum { None, Pie, Static_Pie, Shared_Library, Rel }

Checksec :: struct {
	relro       : Relro,
	nx          : Nx,
	pie         : Pie,
	canary      : bool,
	textrel     : bool,
	rpath       : string,
	runpath     : string,
	rwx_segment : bool,
	fortified   : int,
	fortifiable : int,
	partial     : int,
	stripped    : bool,
}

// Derived from glibc's exported __*_chk symbols.
FORTIFIABLE := [?]string{
	"asprintf", "confstr", "dprintf", "explicit_bzero", "fdelt", "fgets", "fgets_unlocked",
	"fgetws", "fgetws_unlocked", "fprintf", "fread", "fread_unlocked", "fwprintf", "getcwd",
	"getdomainname", "getgroups", "gethostname", "getlogin_r", "gets", "getwd", "inet_ntop",
	"inet_pton", "longjmp", "mbsnrtowcs", "mbsrtowcs", "mbstowcs", "memcpy", "memmove",
	"mempcpy", "memset", "memset_explicit", "obstack_printf", "obstack_vprintf", "poll",
	"ppoll", "pread", "pread64", "printf", "ptsname_r", "read", "readlink", "readlinkat",
	"realpath", "recv", "recvfrom", "snprintf", "sprintf", "stpcpy", "stpncpy", "strcat",
	"strcpy", "strlcat", "strlcpy", "strncat", "strncpy", "swprintf", "syslog", "ttyname_r",
	"vasprintf", "vdprintf", "vfprintf", "vfwprintf", "vprintf", "vsnprintf", "vsprintf",
	"vswprintf", "vsyslog", "vwprintf", "wcpcpy", "wcpncpy", "wcrtomb", "wcscat", "wcscpy",
	"wcslcat", "wcslcpy", "wcsncat", "wcsncpy", "wcsnrtombs", "wcsrtombs", "wcstombs", "wctomb",
	"wmemcpy", "wmemmove", "wmempcpy", "wmemset", "wprintf",
}

checksec :: proc(info: ^ELF_Info) -> Checksec {
	c: Checksec

	c.relro = relro_state(info)
	c.nx = nx_state(info)
	c.pie = pie_state(info)
	c.canary = has_symbol(info, "__stack_chk_fail") || has_symbol(info, "__stack_chk_guard")
	c.textrel = has_textrel(info)
	c.rpath = info.rpath
	c.runpath = info.runpath
	c.rwx_segment = has_rwx_segment(info)
	c.stripped = len(info.symbols) == 0
	c.fortified, c.fortifiable, c.partial = fortify_counts(info)

	return c
}

relro_state :: proc(info: ^ELF_Info) -> Relro {
	relro := false
	for ph in info.program_hdrs {
		if ph.type == PT_GNU_RELRO {
			relro = true
			break
		}
	}
	if !relro {
		return .None
	}

	if _, ok := dyn_val(info, DT_BIND_NOW); ok {
		return .Full
	}
	if flags, ok := dyn_val(info, DT_FLAGS); ok && flags & DF_BIND_NOW != 0 {
		return .Full
	}
	if flags1, ok := dyn_val(info, DT_FLAGS_1); ok && flags1 & DF_1_NOW != 0 {
		return .Full
	}
	return .Partial
}

// An absent PT_GNU_STACK is not the same as NX on: the kernel falls back to a
// build-time default, so the honest answer is unknown.
nx_state :: proc(info: ^ELF_Info) -> Nx {
	for ph in info.program_hdrs {
		if ph.type == PT_GNU_STACK {
			return .Disabled if ph.flags & PF_X != 0 else .Enabled
		}
	}
	return .Unknown
}

// ET_DYN alone does not mean PIE: shared libraries are ET_DYN too.
pie_state :: proc(info: ^ELF_Info) -> Pie {
	if info.header.type == ET_REL {
		return .Rel
	}
	if info.header.type != ET_DYN {
		return .None
	}

	has_interp := false
	for ph in info.program_hdrs {
		if ph.type == PT_INTERP {
			has_interp = true
			break
		}
	}
	if has_interp {
		return .Pie
	}

	flags1, _ := dyn_val(info, DT_FLAGS_1)
	if flags1 & DF_1_PIE != 0 {
		return .Static_Pie
	}
	if _, ok := dyn_val(info, DT_SONAME); ok {
		return .Shared_Library
	}
	return .Shared_Library
}

has_textrel :: proc(info: ^ELF_Info) -> bool {
	if _, ok := dyn_val(info, DT_TEXTREL); ok {
		return true
	}
	flags, _ := dyn_val(info, DT_FLAGS)
	return flags & DF_TEXTREL != 0
}

has_rwx_segment :: proc(info: ^ELF_Info) -> bool {
	for ph in info.program_hdrs {
		if ph.type != PT_LOAD {
			continue
		}
		if ph.flags & PF_W != 0 && ph.flags & PF_X != 0 {
			return true
		}
	}
	return false
}

has_symbol :: proc(info: ^ELF_Info, name: string) -> bool {
	for sym in info.dyn_symbols {
		if sym.name == name {
			return true
		}
	}
	for sym in info.symbols {
		if sym.name == name {
			return true
		}
	}
	return false
}

// __stack_chk_fail is the canary, not a fortified call, so it is excluded.
fortify_counts :: proc(info: ^ELF_Info) -> (fortified: int, fortifiable: int, partial: int) {
	seen_chk := make(map[string]bool)
	seen_raw := make(map[string]bool)
	defer delete(seen_chk)
	defer delete(seen_raw)

	for sym in info.dyn_symbols {
		if sym.name == "" || sym.name == "__stack_chk_fail" || sym.name == "__stack_chk_guard" {
			continue
		}
		if strings.has_prefix(sym.name, "__") && strings.has_suffix(sym.name, "_chk") {
			seen_chk[sym.name[2 : len(sym.name) - 4]] = true
		} else {
			seen_raw[sym.name] = true
		}
	}

	for name in FORTIFIABLE {
		switch {
		case seen_chk[name]:
			fortified += 1
			fortifiable += 1
			if seen_raw[name] {
				partial += 1
			}
		case seen_raw[name]:
			fortifiable += 1
		}
	}
	return
}

relro_str :: proc(r: Relro) -> string {
	switch r {
	case .Full:    return "Full"
	case .Partial: return "Partial"
	case .None:    return "None"
	}
	return "None"
}

nx_str :: proc(n: Nx) -> string {
	switch n {
	case .Enabled:  return "Enabled"
	case .Disabled: return "Disabled"
	case .Unknown:  return "Unknown (no PT_GNU_STACK)"
	}
	return "Unknown"
}

pie_str :: proc(p: Pie) -> string {
	switch p {
	case .Pie:            return "PIE"
	case .Static_Pie:     return "Static PIE"
	case .Shared_Library: return "Shared library (not an executable)"
	case .Rel:            return "Relocatable object"
	case .None:           return "None (ET_EXEC)"
	}
	return "None"
}
