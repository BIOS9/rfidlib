# rfidlib/rust

A Rust library for reading and writing Gallagher access control credentials on NFC smart cards. Targets MIFARE Classic and MIFARE DESFire cards via an ACR122u USB reader.

## Workspace crates

| Crate | Purpose |
|---|---|
| `gallagher-rfid-core/` | Pure protocol logic — no_std compatible, no hardware dependency |
| `gallagher-rfid-pcsc/` | PC/SC hardware integration (ACR122u USB NFC reader) |
| `gallagher-rfid-cli/` | CLI binary |

## Key abstractions

**DESFire**
- `Transport` trait (`gallagher-rfid-core/src/mifare/desfire/transport.rs`) — low-level byte exchange; swap implementations to mock hardware
- `Desfire<T, C>` (`gallagher-rfid-core/src/mifare/desfire/client.rs`) — high-level command client, generic over transport and framing codec
- `FrameCodec` trait — `NativeFraming` vs `WrappedFraming` (ISO-DEP/T=CL, used by PC/SC)
- `Session` enum (`session.rs`) — explicit state machine tracking unauthenticated vs authenticated DESFire sessions; supports AES, DES, 2TDEA, 3TDEA

**MIFARE Classic**
- `Tag` / `KeyProvider` traits (`gallagher-rfid-core/src/mifare/classic/tag.rs`) — abstract card interface
- `GallagherMifareClassic` — reads MAD and CAD to locate and decode credentials

**Credentials**
- `GallagherCredential` (`gallagher-rfid-core/src/gallagher/credential.rs`) — encodes region (4 bits), facility code (16 bits), card number (24 bits), issue level (4 bits) using a custom byte substitution table

## Patterns and conventions

- `heapless::Vec` used throughout for bounded, zero-alloc collections
- `gallagher-rfid-core` is `no_std`; std is feature-gated
- All tests are inline `#[cfg(test)]` blocks — there are no separate `tests/` directories
- Integration tests require real hardware; run via the `desfire-integration` CLI subcommand

## CLI subcommands

`read`, `write`, `desfire`, `desfire-integration`, `desfire-format`, `desfire-provision`, `desfire-changekey`, `desfire-delete`

## Build and test

```sh
cargo build
cargo test
cargo run --bin gallagher-rfid-cli -- <subcommand>
```

## Code quality requirements

All of the following must pass before any change is considered complete:

```sh
cargo test          # all tests must pass
cargo clippy        # zero warnings (workspace has strict pedantic lints configured)
cargo fmt --check   # code must be formatted exactly as rustfmt produces
```

Do not add `#[allow(...)]` attributes to suppress clippy warnings unless there is a clear, specific reason — fix the underlying issue instead.

## Testing standards

The codebase should have extensive unit test coverage. Many tests are based on real-world trace data captured from physical tags (e.g. DESFire sessions captured via Proxmark3). When implementing or modifying protocol logic:

- Prefer tests derived from real traces over purely synthetic test vectors where possible
- Verify both the happy path and error/edge cases
- Cryptographic operations (session key derivation, CMAC, encryption/decryption) must have test coverage with known-good values from real hardware captures
