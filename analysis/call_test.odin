package analysis

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
test_report_status_maps_exit_and_signal :: proc(t: ^testing.T) {
	testing.expect_value(t, report_status(0), "")
	testing.expect_value(t, report_status(101 << 8), "dlopen failed, see above")
	testing.expect_value(t, report_status(102 << 8), "symbol not found, see above")
	testing.expect(t, report_status(3 << 8) != "", "a non-zero exit must be an error")
	testing.expect_value(t, report_status(11), "callee died on signal 11")
}
