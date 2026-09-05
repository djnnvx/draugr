package elf

import "core:encoding/json"
import "core:testing"

// build_json_dump and checksec both use the temp allocator; a free_all inside
// either one frees the other's slices, which crashed the whole --json path.
@(test)
test_json_dump_survives_checksec_allocations :: proc(t: ^testing.T) {
	data := build_dynamic_elf(true, true, DEFAULT_DYN_ENTRIES[:])
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	append(&info.dyn_symbols, Symbol{name = "__memcpy_chk"})
	append(&info.dyn_symbols, Symbol{name = "memcpy"})

	dump := build_json_dump(&info, context.temp_allocator)
	defer free_all(context.temp_allocator)

	testing.expect_value(t, len(dump.needed), 2)
	testing.expect_value(t, dump.needed[0], "libtest.so.1")
	testing.expect_value(t, dump.runpath, "/opt/runpath")
	testing.expect_value(t, dump.checksec.fortified, 1)

	out, err := json.marshal(dump, {pretty = true}, context.temp_allocator)
	testing.expect(t, err == nil, "marshal must succeed")
	testing.expect(t, len(out) > 0, "marshal must produce output")
}

@(test)
test_json_dump_round_trips_through_parser :: proc(t: ^testing.T) {
	data := build_dynamic_elf(true, true, DEFAULT_DYN_ENTRIES[:])
	defer delete(data)

	info, _ := load(data)
	defer destroy(&info)

	dump := build_json_dump(&info, context.temp_allocator)
	out, _ := json.marshal(dump, {}, context.temp_allocator)
	defer free_all(context.temp_allocator)

	parsed, perr := json.parse(out, allocator = context.temp_allocator)
	testing.expect(t, perr == nil, "emitted JSON must parse back")

	obj := parsed.(json.Object)
	testing.expect_value(t, obj["soname"].(json.String), "libtest.so.1")
	testing.expect_value(t, obj["class"].(json.Float), 64)
}
