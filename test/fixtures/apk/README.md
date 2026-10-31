# Android fixtures

Our own app description, written into an APK and an AAB by `build.mjs`. No third-party code, binary
or tool output is checked in apart from the JDK's `jarsigner` signature over our own files.

| File | What it carries |
| --- | --- |
| `chibitek-fixture.apk` | Binary XML manifest for `com.chibitek.fixture` 1.0.7 (min SDK 24, target 34): two requested permissions, one declared signature permission, a camera feature, an exported launcher activity with an https deep link, a permission-guarded service, an exported boot receiver and a provider. One DEX with two classes and four methods, one of which loads an embedded URL. `libchibi.so` for `arm64-v8a` and `armeabi-v7a`, stored uncompressed (copied from `../elf`). Signed v1 by `jarsigner`, with v2 and v3 blocks added by the builder |
| `chibitek-fixture.apk.idsig` | The v4 signature for that APK |
| `chibitek-fixture.aab` | The same app as a one-module bundle: aapt2 protobuf manifest, the same DEX, the `arm64-v8a` library |

Built with network access denied. The signing key is generated in a temporary folder for each build
and deleted with it, so a rebuild produces a new certificate and new bytes:

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)' node build.mjs
```

Needs the Homebrew `openjdk@25` (`keytool`, `jarsigner`), `/usr/bin/zip` and `/usr/bin/openssl`.
`jarsigner -verify` accepts the APK. v2, v3 and v4 follow the published formats but were not checked
by `apksigner`, which is not installed. The files are never installed or run.
