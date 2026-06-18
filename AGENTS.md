# AGENTS.md

Instructions for coding agents working in this repository.

## Project Scope

- This repository is the Rust rewrite of tinc. The active source tree is the
  Cargo workspace at the repository root.
- Maintain compatibility with the official upstream C tinc implementation.
  Protocol behavior, configuration semantics, command-line/control behavior,
  and network interoperability should match upstream C tinc unless a deliberate
  incompatibility is documented and justified.
- Keep upstream C tinc code only in the `vendor/tinc` Git submodule.
- Do not add, restore, or copy C source files, Meson project files, or other
  upstream C implementation files into the Rust workspace outside `vendor/tinc`.
- Use `vendor/tinc` only as a reference implementation for C/Rust
  interoperability tests.

## Repository Hygiene

- Preserve `vendor/tinc` as a Git submodule. Do not vendor it as ordinary files.
- When adding features or changing behavior, first check that `vendor/tinc` is
  initialized. If the official C tinc submodule is missing or empty, run
  `git submodule update --init --recursive vendor/tinc` before implementing the
  change.
- Do not commit Rust `target/` output, C build directories, netns logs, timing
  reports, backup archives, or generated binaries.
- Keep generated C reference builds under ignored paths such as:
  - `vendor/tinc/build-c`
  - `vendor/tinc/build-c-zlib`
  - `vendor/tinc/build-c-compression`
  - `vendor/tinc/build-c-lz4`
- Before broad edits, inspect `git status --short` and avoid reverting user
  changes.

## Fixing Bugs

- Fix the root cause in the Rust implementation or test support code.
- Do not make superficial fixes that merely hide failures.
- Do not delete failing production code to make tests pass.
- Do not suppress, ignore, or mask errors instead of handling them correctly.
- Do not change tests to fit broken existing behavior when the Rust code is
  wrong.
- If a test reveals a missing runtime/build dependency, make that dependency
  explicit or robustly discoverable rather than relying on a manual local state.

## Rust Development

- Prefer existing crate boundaries:
  - `crates/tinc-core` for protocol, graph, route, subnet, and utility logic.
  - `crates/tinc-runtime` for transport, device, key exchange, meta, and SPTPS.
  - `crates/tincctl` for the Rust `tinc` control command.
  - `crates/tincd` for the daemon and daemon-facing integration behavior.
  - `crates/tinc-test-support` for shared test helpers.
- Keep behavior compatible with tinc 1.1 where compatibility is already tested
  or documented.
- When changing behavior that overlaps with official C tinc, compare against
  `vendor/tinc` and add or update Rust tests that preserve C-compatible
  behavior.
- Use structured protocol/config parsers already present in the workspace
  rather than ad hoc string parsing.

## Required Test Discipline

- For normal Rust verification, run:

```sh
cargo test --workspace --all-targets
```

- For privileged network namespace tests, run as root with strict netns enabled:

```sh
TINC_NETNS_STRICT=1 cargo test -p tincd --test netns_smoke
```

- Full C/Rust netns interoperability requires C reference binaries from
  `vendor/tinc`:

```sh
meson setup vendor/tinc/build-c vendor/tinc
ninja -C vendor/tinc/build-c

meson setup vendor/tinc/build-c-zlib vendor/tinc -Dzlib=enabled
ninja -C vendor/tinc/build-c-zlib

meson setup vendor/tinc/build-c-compression vendor/tinc -Dzlib=enabled -Dlz4=enabled
ninja -C vendor/tinc/build-c-compression

meson setup vendor/tinc/build-c-lz4 vendor/tinc -Dlz4=enabled
ninja -C vendor/tinc/build-c-lz4
```

- When running strict C/Rust netns tests, use or verify these environment
  variables:

```sh
export C_TINCD_PATH="$PWD/vendor/tinc/build-c/src/tincd"
export C_TINC_PATH="$PWD/vendor/tinc/build-c/src/tinc"
export C_TINCD_ZLIB_PATH="$PWD/vendor/tinc/build-c-zlib/src/tincd"
export C_TINCD_COMPRESSION_PATH="$PWD/vendor/tinc/build-c-compression/src/tincd"
export C_TINCD_LZ4_PATH="$PWD/vendor/tinc/build-c-lz4/src/tincd"
export TINC_NETNS_STRICT=1
```

- The Rust `tinc` CLI is produced by `cargo build -p tincctl --bin tinc`.
  Tests that need the CLI should not assume it exists unless they build it or
  locate it explicitly.

## Full Per-Item Test Reports

When asked to run the complete test suite with per-item timing:

- Run every libtest item individually, not only each test binary as a whole.
- Include ignored tests by passing `--include-ignored` where applicable.
- Use `--exact --test-threads=1 --nocapture` for each individual item.
- Record one Markdown table row per test item with:
  - item name
  - target/crate
  - status
  - wall-clock duration
  - a short description of the scenario or code path being tested
  - log path
- Write the report into the current working directory requested by the user.
- Preserve raw logs and JSONL/progress files for later diagnosis.
- Some netns tests can run for many minutes. Wait for them to finish unless the
  process is clearly dead and you have evidence.
- After long netns runs, check for leftover `tincd`, `netns_smoke`, `iperf3`,
  and network namespaces.

## Netns Expectations

- Use root privileges when strict netns tests are requested.
- Required tools commonly include `ip`, `ping`, `arping`, `iperf3`, and
  `tcpdump`.
- Do not silently convert a strict netns failure into a skip. In strict mode,
  missing privileges, missing tools, or missing C reference binaries are real
  setup failures.
