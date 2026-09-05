package elf

import "core:testing"

checksec_info :: proc(phdrs: []Program_Header, dyn: [][2]u64) -> ELF_Info {
	info: ELF_Info
	info.program_hdrs = make([dynamic]Program_Header)
	info.section_hdrs = make([dynamic]Section_Header)
	info.symbols = make([dynamic]Symbol)
	info.dyn_symbols = make([dynamic]Symbol)
	info.dyn_entries = make([dynamic]Dyn_Entry)
	info.needed = make([dynamic]string)
	info.relocs = make([dynamic]Reloc)
	info.header.type = ET_DYN

	for p in phdrs {
		append(&info.program_hdrs, p)
	}
	for e in dyn {
		append(&info.dyn_entries, Dyn_Entry{tag = e[0], val = e[1]})
	}
	return info
}

@(test)
test_relro_needs_bind_now_for_full :: proc(t: ^testing.T) {
	none := checksec_info({}, {})
	defer destroy(&none)
	testing.expect_value(t, relro_state(&none), Relro.None)

	partial := checksec_info({{type = PT_GNU_RELRO}}, {})
	defer destroy(&partial)
	testing.expect_value(t, relro_state(&partial), Relro.Partial)

	full := checksec_info({{type = PT_GNU_RELRO}}, {{DT_FLAGS, DF_BIND_NOW}})
	defer destroy(&full)
	testing.expect_value(t, relro_state(&full), Relro.Full)

	full1 := checksec_info({{type = PT_GNU_RELRO}}, {{DT_FLAGS_1, DF_1_NOW}})
	defer destroy(&full1)
	testing.expect_value(t, relro_state(&full1), Relro.Full)
}

@(test)
test_nx_absent_segment_is_unknown :: proc(t: ^testing.T) {
	unknown := checksec_info({}, {})
	defer destroy(&unknown)
	testing.expect_value(t, nx_state(&unknown), Nx.Unknown)

	on := checksec_info({{type = PT_GNU_STACK, flags = PF_R | PF_W}}, {})
	defer destroy(&on)
	testing.expect_value(t, nx_state(&on), Nx.Enabled)

	off := checksec_info({{type = PT_GNU_STACK, flags = PF_R | PF_W | PF_X}}, {})
	defer destroy(&off)
	testing.expect_value(t, nx_state(&off), Nx.Disabled)
}

@(test)
test_pie_distinguishes_shared_library_from_executable :: proc(t: ^testing.T) {
	pie := checksec_info({{type = PT_INTERP}}, {})
	defer destroy(&pie)
	testing.expect_value(t, pie_state(&pie), Pie.Pie)

	lib := checksec_info({}, {{DT_SONAME, 1}})
	defer destroy(&lib)
	testing.expect_value(t, pie_state(&lib), Pie.Shared_Library)

	spie := checksec_info({}, {{DT_FLAGS_1, DF_1_PIE}})
	defer destroy(&spie)
	testing.expect_value(t, pie_state(&spie), Pie.Static_Pie)

	exe := checksec_info({}, {})
	defer destroy(&exe)
	exe.header.type = ET_EXEC
	testing.expect_value(t, pie_state(&exe), Pie.None)
}

@(test)
test_rwx_and_textrel_are_flagged :: proc(t: ^testing.T) {
	clean := checksec_info({{type = PT_LOAD, flags = PF_R | PF_X}}, {})
	defer destroy(&clean)
	testing.expect(t, !has_rwx_segment(&clean), "R X segment is not RWX")
	testing.expect(t, !has_textrel(&clean), "no DT_TEXTREL")

	rwx := checksec_info({{type = PT_LOAD, flags = PF_R | PF_W | PF_X}}, {{DT_TEXTREL, 0}})
	defer destroy(&rwx)
	testing.expect(t, has_rwx_segment(&rwx), "RWX PT_LOAD must be flagged")
	testing.expect(t, has_textrel(&rwx), "DT_TEXTREL must be flagged")

	flagged := checksec_info({}, {{DT_FLAGS, DF_TEXTREL}})
	defer destroy(&flagged)
	testing.expect(t, has_textrel(&flagged), "DF_TEXTREL must be flagged")
}

@(test)
test_fortify_excludes_stack_canary :: proc(t: ^testing.T) {
	info := checksec_info({}, {})
	defer destroy(&info)

	append(&info.dyn_symbols, Symbol{name = "__stack_chk_fail"})
	append(&info.dyn_symbols, Symbol{name = "__memcpy_chk"})
	append(&info.dyn_symbols, Symbol{name = "memcpy"})
	append(&info.dyn_symbols, Symbol{name = "strcpy"})

	fortified, fortifiable, partial := fortify_counts(&info)
	testing.expect_value(t, fortified, 1)
	testing.expect_value(t, fortifiable, 2)
	testing.expect_value(t, partial, 1)

	c := checksec(&info)
	testing.expect(t, c.canary, "__stack_chk_fail must still set the canary flag")
}
