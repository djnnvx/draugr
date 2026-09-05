package analysis

import "core:fmt"
import "core:math"
import "core:os"

calculate_entropy :: proc(data: []u8) -> f64 {
	if len(data) == 0 {
		return 0.0
	}
	
	freq: [256]f64
	for b in data {
		freq[b] += 1.0
	}
	
	total := f64(len(data))
	entropy := 0.0
	for i := 0; i < len(freq); i += 1 {
		f := freq[i]
		if f > 0 {
			p := f / total
			entropy -= p * math.log_f64(p, 2)
		}
	}
	
	return entropy
}

entropy_output :: proc(data: []u8, out_path: string) -> string {
	f, err := open_out(out_path)
	if err != "" {
		return err
	}
	defer close_out(f, out_path)

	block_size := 256
	fmt.fprintf(f, "Entropy Analysis (block size: %d bytes)\n", block_size)
	fmt.fprintf(f, "%-12s %-6s %s\n", "Offset", "Size", "Entropy")
	fmt.fprintf(f, "%s\n", "----------------------------------------")
	
	for i := 0; i < len(data); i += block_size {
		end := i + block_size
		if end > len(data) {
			end = len(data)
		}
		
		block := data[i:end]
		entropy := calculate_entropy(block)
		
		// Odin's fmt zero-fills numeric widths, so pad via a string for alignment.
		fmt.fprintf(f, "0x%08x   %-6s %.4f\n", i, fmt.tprintf("%d", len(block)), entropy)
	}
	
	overall := calculate_entropy(data)
	fmt.fprintf(f, "\nOverall entropy: %.4f bits/byte\n", overall)
	
	if overall < 4.0 {
		fmt.fprintf(f, "Classification: Low entropy (text/code)\n")
	} else if overall < 7.0 {
		fmt.fprintf(f, "Classification: Medium entropy (mixed)\n")
	} else {
		fmt.fprintf(f, "Classification: High entropy (compressed/encrypted)\n")
	}
	
	return ""
}
