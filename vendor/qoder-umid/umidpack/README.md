# umidpack — native identity binaries (Linux x86-64 only in this tree)

Extracted verbatim from the official `@qoder-ai/qodercli` bundle
(`package/bundle/qoder-worker-runtime.mjs`, base64-embedded blobs — the same
technique as the donor hub's `_install_umid.py`).

## Targets

| Path | Platform | Format | Deps |
|---|---|---|---|
| `elf-x86_64/runtime-info` | Linux x86-64 | ELF | libstdc++/libm/libpthread/libdl/libc (glibc ≤ 2.28) — see `../qoder-umid-mini.tar.gz` for the bundled libs |

The upstream bundle also ships `elf-aarch64`, `macho-x86_64`, and the Windows
`runtime-info.exe` + `sgsdk.dll` pair. They are **not carried here**: this tree
is trimmed to the single target the deployment host runs, because the hosting
platform caps repository size. `pickBridge()` in
`src/providers/integrations/qoder/qoder-umid.ts` returns `null` when no bridge
matches the host, and dispatch falls back to the deterministic generated
identity — so a missing binary degrades to a warning, not a crash.

CLI contract (upstream, donor-verified):

```
runtime-info <env>                        # linux
printf '{"account":"<uid>"}\n' | runtime-info <env> --account-stdin   # darwin / win32
```

`env`: 0 default, 3 current CLI, 4 desktop. Output: one JSON line
`{machineToken, machineType, machineCode, vmInfo, …}`.

## Identity semantics (verified 2026-10-30)

- The identity is a deterministic function of the seed file
  `~/.config/.locale_cfg` (same path on Linux/macOS/WSL; the Windows exe
  ignores it and is hardware-bound, one identity per machine).
- Seed deleted → fresh identity; seed restored → identical identity. One
  seed per account, portable across OS hosts.
- Linux reports `isVm:false` on normal hosts; `vmInfo` is local-only output
  and is never sent upstream (only the six `cosy-machine*` headers are).
