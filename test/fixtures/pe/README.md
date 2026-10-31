# PE fixtures

Our own code (`Fixture.cs`), compiled offline with the Roslyn compiler that ships in the .NET 10 SDK.
No third-party binary is checked in. Builds are deterministic, so the same command reproduces the same
bytes.

| File | Platform | Format | Machine |
| --- | --- | --- | --- |
| `fixture-anycpu.dll` | `anycpu` | PE32 | x86 (0x14c), imports `mscoree.dll!_CorDllMain` |
| `fixture-x64.dll` | `x64` | PE32+ | x64 (0x8664) |
| `fixture-arm64.dll` | `arm64` | PE32+ | ARM64 (0xaa64) |

Each references System.Runtime, System.Net.Http and System.Text.Json and carries a version resource
with CompanyName "Chibitek". Compiled with network access denied:

```sh
D=/opt/homebrew/Cellar/dotnet/10.0.400/libexec
R=$D/packs/Microsoft.NETCore.App.Ref/10.0.11/ref/net10.0
for p in anycpu x64 arm64; do
  sandbox-exec -p '(version 1)(allow default)(deny network*)' \
    $D/dotnet $D/sdk/10.0.400/Roslyn/bincore/csc.dll -nologo -noconfig -nostdlib -deterministic -optimize \
    -target:library -platform:$p -out:fixture-$p.dll \
    -r:$R/System.Runtime.dll -r:$R/System.Net.Http.dll -r:$R/System.Text.Json.dll Fixture.cs
done
```

The DLLs are never executed. They exist only to be parsed.
