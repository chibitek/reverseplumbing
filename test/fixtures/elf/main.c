// ReversePlumbing ELF fixture: executable | Chibitek Engineering | 2026-10-24
// Never executed; it exists to be parsed. See test/fixtures/elf/README.md.
int chibi_add(int, int);
void _start(void) { for (;;) chibi_add(1, 2); }
