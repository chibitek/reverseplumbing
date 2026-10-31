# ELF fixtures

Our own C (`chibi.c`, `main.c`, `chibi.map`), compiled offline by Homebrew clang and linked by the
lld that ships with rustup. No third-party binary is checked in. Builds are deterministic, so
`bash build.sh` reproduces the same bytes.

| File | Class, byte order | Machine | What it carries |
| --- | --- | --- | --- |
| `libchibi-aarch64.so` | ELF64, little | AArch64 | soname `libchibi.so.1`, version `CHIBI_1.0`, four exports (one weak), imports `puts`, BTI/PAC/GCS property note |
| `fixture-aarch64` | ELF64, little | AArch64 | PIE, interpreter `/lib/ld-linux-aarch64.so.1`, needs `libchibi.so.1`, imports `chibi_add@CHIBI_1.0`, runpath `$ORIGIN`, full RELRO, NX stack |
| `libchibi-aarch64_be.so`, `fixture-aarch64_be` | ELF64, big | AArch64 | The same, big-endian |
| `libchibi-armhf.so`, `fixture-armhf` | ELF32, little | ARM (Thumb-2) | The same, EABI5 hard-float |

Every file carries a SHA-1 build-id. Built with network access denied:

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)' bash build.sh
```

The binaries are never executed. They exist only to be parsed.
