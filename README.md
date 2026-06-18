# tinc Rust Rewrite

This repository contains a Rust implementation of the tinc 1.1 VPN daemon and
control tool. The active project code is managed as a Cargo workspace. The
original C implementation is kept only as a Git submodule under `vendor/tinc`
so that interoperability tests can compare the Rust implementation with the
upstream behavior.

The code is still under active development. Treat command-line compatibility,
configuration compatibility, and C/Rust network interoperability as project
goals that must be verified by tests before relying on a build in production.

## Repository Layout

| Path | Purpose |
|---|---|
| `Cargo.toml` | Workspace definition for all Rust crates. |
| `crates/tinc-core` | Core protocol, routing, graph, subnet, and utility logic. |
| `crates/tinc-runtime` | Runtime transport, device, meta connection, key exchange, and SPTPS logic. |
| `crates/tincctl` | Rust `tinc` control command. |
| `crates/tincd` | Rust `tincd` daemon and integration tests. |
| `crates/tinc-test-support` | Shared test helpers. |
| `vendor/tinc` | Upstream C tinc submodule, used only for C/Rust interoperability tests. |

## Prerequisites

- Rust toolchain with Cargo and the edition used by this workspace.
- Linux with `/dev/net/tun` and `iproute2` for network namespace tests.
- `ping`, `arping`, `iperf3`, and `tcpdump` for the full privileged netns test
  gate.
- C build dependencies for the upstream tinc submodule only when running
  C/Rust interoperability tests.

## Build

Build every Rust crate:

```sh
cargo build --workspace
```

Build only the daemon or control tool:

```sh
cargo build -p tincd
cargo build -p tincctl
```

The resulting binaries are:

```text
target/debug/tincd
target/debug/tinc
```

## Basic Usage

Create or prepare a tinc configuration directory, then start the Rust daemon:

```sh
target/debug/tincd -D -c /path/to/tinc/conf
```

Use the Rust control tool against the same configuration directory:

```sh
target/debug/tinc -c /path/to/tinc/conf dump nodes
target/debug/tinc -c /path/to/tinc/conf dump subnets
target/debug/tinc -c /path/to/tinc/conf stop
```

For netname-based layouts, use `-n <netname>` in the same style as tinc:

```sh
target/debug/tincd -n mynet -D
target/debug/tinc -n mynet dump nodes
```

## Tests

Run the Rust test suite:

```sh
cargo test --workspace --all-targets
```

Some integration tests require Linux network namespaces and root privileges. To
require the full privileged netns environment instead of silently skipping
interop tests, set:

```sh
TINC_NETNS_STRICT=1 cargo test -p tincd --test netns_smoke
```

## C Reference Submodule

Initialize the upstream C tinc reference implementation:

```sh
git submodule update --init --recursive
```

The submodule is pinned under:

```text
vendor/tinc
```

Build the default C reference binaries for interoperability tests:

```sh
meson setup vendor/tinc/build-c vendor/tinc
ninja -C vendor/tinc/build-c
```

Optional C reference builds used by specific compression compatibility tests:

```sh
meson setup vendor/tinc/build-c-zlib vendor/tinc -Dzlib=enabled
ninja -C vendor/tinc/build-c-zlib

meson setup vendor/tinc/build-c-compression vendor/tinc -Dzlib=enabled -Dlz4=enabled
ninja -C vendor/tinc/build-c-compression

meson setup vendor/tinc/build-c-lz4 vendor/tinc -Dlz4=enabled
ninja -C vendor/tinc/build-c-lz4
```

By default, the Rust netns tests look for C binaries at:

```text
vendor/tinc/build-c/src/tincd
vendor/tinc/build-c/src/tinc
vendor/tinc/build-c-zlib/src/tincd
vendor/tinc/build-c-compression/src/tincd
vendor/tinc/build-c-lz4/src/tincd
```

You can override those paths explicitly:

```sh
export C_TINCD_PATH=/absolute/path/to/tincd
export C_TINC_PATH=/absolute/path/to/tinc
export C_TINCD_ZLIB_PATH=/absolute/path/to/zlib-enabled/tincd
export C_TINCD_COMPRESSION_PATH=/absolute/path/to/compression-enabled/tincd
export C_TINCD_LZ4_PATH=/absolute/path/to/lz4-enabled/tincd
```

## Development Notes

- Keep production Rust code and Rust tests in the Cargo workspace.
- Keep upstream C code inside `vendor/tinc`; do not copy C source files back
  into the Rust workspace.
- Use C binaries only as reference peers for compatibility and regression
  tests.
- Prefer adding focused Rust unit tests for protocol and runtime logic, and
  netns smoke tests only when behavior depends on real Linux networking.

## License

This project follows tinc's GPL-2.0-or-later licensing. See `COPYING` for the
license text.
