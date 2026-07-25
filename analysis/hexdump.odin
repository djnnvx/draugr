// analysis/hexdump.odin - Hex dump functionality
package analysis

import "core:fmt"
import "core:os"

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

HexdumpConfig :: struct {
	width       : int,
	show_offset : bool,
	show_ascii  : bool,
}

default_config :: proc() -> HexdumpConfig {
	return HexdumpConfig{
		width = 16,
		show_offset = true,
		show_ascii = true,
	}
}

// hexdump performs a hex dump of data to stdout or file
// Returns empty string on success, error message on failure
hexdump :: proc(data: []u8, offset: u64, out_path: string) -> string {
	cfg := default_config()

	f, err := open_out(out_path)
	if err != "" {
		return err
	}
	defer close_out(f, out_path)


	for i := 0; i < len(data); i += cfg.width {
		if cfg.show_offset {
			fmt.fprintf(f, "%08x  ", offset + u64(i))
		}
		
		for j := 0; j < cfg.width; j += 1 {
			if i + j < len(data) {
				fmt.fprintf(f, "%02x ", data[i + j])
			} else {
				fmt.fprintf(f, "   ")
			}
		}
		
		if cfg.show_ascii {
			fmt.fprintf(f, " |")
			for j := 0; j < cfg.width; j += 1 {
				if i + j < len(data) {
					c := data[i + j]
					if c >= 32 {
						if c <= 126 {
							fmt.fprintf(f, "%c", c)
						} else {
							fmt.fprintf(f, ".")
						}
					} else {
						fmt.fprintf(f, ".")
					}
				} else {
					fmt.fprintf(f, " ")
				}
			}
			fmt.fprintf(f, "|")
		}
		
		fmt.fprintf(f, "\n")
	}
	
	return ""
}