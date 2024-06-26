# mbn-rs

Toolkit for parse MBN format.

Basically, it's a Rust rewrite of the relevant parts of [readmbn](https://github.com/openpst/readmbn).

MBN format information comes from [coreboot](https://www.coreboot.org/).

[A library](https://docs.rs/mbn) and a CLI tool are available.

## Install CLI tool

### Download prebuilt binary

Download prebuilt binary from the [Github release page](https://github.com/NichtsHsu/mbn-rs/releases/latest).

### Install from source

```bash
cargo install mbn-cli
```

## CLI tool usage

Just `mbn-cli path/to/mbn/file`, then you can see a lot of information printed on your shell.

Check `mbn-cli --help` for detailed usage.

**NOTE**: Extension of files with MBN segment may be `elf`. Files with extension `mbn` are almost ELF format files.
