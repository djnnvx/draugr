# draugr

ELF mapping and analysis tool. Parses ELF32/ELF64, little and big endian, and reports
sections, segments, symbols, entropy and memory layout.

Written in Odin with no external dependencies. Odin ships no ELF package, so the parser
is hand-rolled; byte reads go through `core:encoding/endian`.

## Build

```sh
asdf install
odin build . -out:draugr
```

## Usage

```
draugr <elf-path> [flags]
```

| Flag | Description |
| --- | --- |
| `--info` | ELF summary only (class, type, machine, entry, PIE, dynamic, counts) |
| `--sections` | Section header table |
| `--segments` | Program header table, objdump -p style |
| `--symbols` | Symbol table, nm style, static and dynamic |
| `--map` | Visual memory layout |
| `--entropy` | Shannon entropy, 256-byte blocks, bits per byte |
| `--hexdump` | Hex dump the whole file |
| `--disasm` | List executable sections with a byte preview |
| `--remap <file>` | Remap against a prototype file (stub) |
| `--json` | JSON output (applies to `--info`) |
| `--verbose` | Verbose output |

`--hexdump`, `--entropy` and `--disasm` each have an `--<name>-out <file>` variant that
writes to a file instead of stdout. Flags combine, so `--sections --symbols` prints both.

Both `--flag value` and `--flag=value` work, and a single dash is accepted.

### Output streams

Data goes to **stdout**. Headers, separators and the `arch=` summary go to **stderr**.
So the tool stays readable on a terminal and pipeable everywhere else.

```sh
draugr --info --json /bin/ls | jq .entry
draugr --sections /bin/ls | awk '$3 == "PROGBITS"'
draugr --symbols /bin/ls | grep ' U '        # undefined imports
```

Exit code is 0 on success, 1 on a read, parse or output-write failure. A failing
`--<name>-out` does not prevent the other requested analyses from running.


