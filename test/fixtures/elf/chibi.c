// ReversePlumbing ELF fixture: shared object | Chibitek Engineering | 2026-10-24
// Built offline with clang and lld; see test/fixtures/elf/README.md.
extern int puts(const char *);
const char *chibi_name(void) { return "Chibitek"; }
int chibi_add(int a, int b) { return a + b; }
__attribute__((weak)) int chibi_weak(void) { return 1; }
int chibi_hello(void) { return puts("ReversePlumbing ELF fixture"); }
