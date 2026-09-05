# draugr

ELF mapping and analysis tool. Written in Odin with no third-party dependencies.

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
| `--checksec` | Hardening report: RELRO, NX, canary, PIE, RPATH, FORTIFY |
| `--relocs` | Relocation table and PLT/GOT map |
| `--code` | Code regions: executable sections with entropy, entry point, function starts |
| `--call-function <sym>` | Load the file from memory and call one symbol |
| `--call-args <list>` | Arguments for `--call-function` |
| `--bin-diff <file>` | Diff this binary's layout against a reference ELF |
| `--json` | Full structured dump: header, segments, sections, dynamic, symbols, relocations, GOT, checksec |
| `--verbose` | Verbose output |

`--hexdump`, `--entropy` and `--code` each have an `--<name>-out <file>` variant that
writes to a file instead of stdout. Flags combine, so `--sections --symbols` prints both.

`--json` covers the whole structured dump on its own and ignores the selector flags. It is
rejected alongside `--hexdump`, `--entropy`, `--code`, `--map`, `--bin-diff` and
`--call-function`, which are visualizations or actions with no JSON form.

Both `--flag value` and `--flag=value` work, and a single dash is accepted.

### Output streams

Data goes to **stdout**. Headers, separators and the `arch=` summary go to **stderr**.
So the tool stays readable on a terminal and pipeable everywhere else.

```sh
draugr --json /bin/ls | jq .needed
draugr --json /bin/ls | jq .checksec
draugr --json /bin/ls | jq .got.fclose       # GOT slot address, pwntools style
draugr --json /bin/ls | jq '.dynamic_entries[] | select(.tag == "RUNPATH")'
draugr --sections /bin/ls | awk '$3 == "PROGBITS"'
draugr --symbols /bin/ls | grep ' U '        # undefined imports
draugr --bin-diff v1.4.2/httpd v1.4.3/httpd  # what changed between firmware builds
```

### Hardening

`--checksec` reports RELRO, stack canary, NX, PIE, RPATH, RUNPATH and FORTIFY. It also
flags `DT_TEXTREL` and any RWX `PT_LOAD` segment.

Three places where it deliberately disagrees with `checksec(1)`:

- **NX with no `PT_GNU_STACK`** reports `Unknown`, not `Enabled`.
- **PIE** separates `PIE`, `Static PIE`, `Shared library` and `ET_EXEC`.
- **FORTIFY** counts distinct functions. `checksec(1)` counts a function twice when it is
  imported both fortified and unfortified.

### Relocations

`--relocs` parses `RELA`, `REL` and `RELR`, from section headers when present and from the
dynamic tags otherwise.

### Dynamic linking

`--info` reports `SONAME`, `RPATH`, `RUNPATH` and the `DT_NEEDED` list. `--info --verbose`
adds the full `.dynamic` table. Unrecognised `DT_` tags print as hex rather than `UNKNOWN`.

### Calling a function

`--call-function` loads the file through a `memfd` and calls a single symbol, without the
linked object ever reaching disk. A `.o` is linked first with `ld -shared` writing straight
into the memfd; a `.so` is written to the memfd as-is.

```sh
draugr --call-function alpha --call-args 21 ./thing.o
draugr --call-function parse --call-args s:AAAA,64 ./libvendor.so
```

Arguments are comma-separated: integers (decimal or `0x`), or `s:text` to pass a pointer to
a NULL-terminated string. Up to six, matching the integer argument registers. Floats and
structs are not supported, and the return value is read as a 64-bit integer.

`.o` support needs `ld` on `$PATH`, and a cross-linker for a foreign architecture.

### Function starts

`--code` recovers function entry addresses from the `.eh_frame_hdr` binary search table.

draugr does not disassemble. Pipe to `objdump -d` for that.


