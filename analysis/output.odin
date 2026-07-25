// analysis/output.odin - stdout-or-file output handles
package analysis

import "core:fmt"
import "core:os"

// An empty out_path means stdout, which must not be closed.
open_out :: proc(out_path: string) -> (^os.File, string) {
	if out_path == "" {
		return os.stdout, ""
	}
	f, err := os.create(out_path)
	if err != nil {
		return nil, fmt.tprintf("cannot create %s: %v", out_path, err)
	}
	return f, ""
}

close_out :: proc(f: ^os.File, out_path: string) {
	if out_path != "" {
		os.close(f)
	}
}
