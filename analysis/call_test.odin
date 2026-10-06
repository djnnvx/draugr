package analysis

import "core:fmt"
import "core:testing"

@(test)
test_call_args_default_to_zero :: proc(t: ^testing.T) {
	args, err := parse_call_args("")
	defer delete(args)

	testing.expect_value(t, err, "")
	testing.expect_value(t, len(args), 6)
	for a in args {
		testing.expect_value(t, a, 0)
	}
}

@(test)
test_call_args_parse_decimal_and_hex :: proc(t: ^testing.T) {
	args, err := parse_call_args("42, 0x2a, -1")
	defer delete(args)

	testing.expect_value(t, err, "")
	testing.expect_value(t, args[0], 42)
	testing.expect_value(t, args[1], 42)
	testing.expect_value(t, i64(args[2]), -1)
	testing.expect_value(t, args[3], 0)
}

@(test)
test_call_args_string_becomes_a_pointer :: proc(t: ^testing.T) {
	args, err := parse_call_args("s:hello")
	defer delete(args)

	testing.expect_value(t, err, "")
	testing.expect(t, args[0] != 0, "s: argument must produce a non-null pointer")

	str := cstring(rawptr(uintptr(args[0])))
	testing.expect_value(t, string(str), "hello")
}

@(test)
test_call_args_reject_junk_and_overflow :: proc(t: ^testing.T) {
	junk, err := parse_call_args("notanumber")
	defer delete(junk)
	testing.expect(t, err != "", "non-numeric argument must be rejected")

	too_many, err2 := parse_call_args("1,2,3,4,5,6,7")
	defer delete(too_many)
	testing.expect(t, err2 != "", "more than 6 arguments must be rejected")
}

@(test)
test_parse_patches :: proc(t: ^testing.T) {
	patches, err := parse_patches("got:puts=my_puts; secret=ret:1; hook=jmp:repl")
	defer delete(patches)

	testing.expect_value(t, err, "")
	testing.expect_value(t, len(patches), 3)

	testing.expect_value(t, patches[0].kind, Patch_Kind.Got)
	testing.expect_value(t, patches[0].target, "puts")
	testing.expect_value(t, patches[0].repl, "my_puts")

	testing.expect_value(t, patches[1].kind, Patch_Kind.Ret)
	testing.expect_value(t, patches[1].target, "secret")
	testing.expect_value(t, patches[1].value, 1)

	testing.expect_value(t, patches[2].kind, Patch_Kind.Jmp)
	testing.expect_value(t, patches[2].target, "hook")
	testing.expect_value(t, patches[2].repl, "repl")

	empty, eerr := parse_patches("")
	defer delete(empty)
	testing.expect_value(t, eerr, "")
	testing.expect_value(t, len(empty), 0)
}

@(test)
test_parse_patches_rejects_junk :: proc(t: ^testing.T) {
	cases := []string{"noequalssign", "f=ret:", "f=ret:xyz", "got:=target", "f=bogus:1"}
	for c in cases {
		p, err := parse_patches(c)
		defer delete(p)
		testing.expect(t, err != "", fmt.tprintf("spec %q must be rejected", c))
	}
}

@(test)
test_report_status_maps_exit_and_signal :: proc(t: ^testing.T) {
	testing.expect_value(t, report_status(0), "")
	testing.expect_value(t, report_status(101 << 8), "dlopen failed, see above")
	testing.expect_value(t, report_status(102 << 8), "symbol not found, see above")
	testing.expect(t, report_status(3 << 8) != "", "a non-zero exit must be an error")
	testing.expect_value(t, report_status(11), "callee died on signal 11")
}
