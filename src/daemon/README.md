# Airpipe Daemon Module Structure

The daemon implementation has been split from the original monolithic `src/daemon.rs` into smaller modules, organized by responsibility.

The refactoring keeps the existing daemon API and protocol behavior intact while making the implementation easier to navigate, maintain, and extend.

## Directory Layout

```text
src/
├── daemon.rs                 # Daemon module entry point and public API
└── daemon/
    ├── conn.rs               # Connection I/O and result synchronization
    ├── state.rs              # Shared daemon and session state
    ├── session.rs            # Session lifecycle and protocol dispatch
    ├── file_transfer.rs      # Outbound file transfer
    ├── clipboard_sync.rs     # Clipboard synchronization
    └── util.rs               # Shared utility functions
```

The project uses the directory-based module layout with `src/daemon.rs` as the parent module. Submodules are declared from this file and their implementations reside in `src/daemon/`.

This avoids introducing an additional `mod.rs` while keeping the module hierarchy explicit.

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `daemon.rs` | Daemon initialization, listener setup, accept loop, shutdown, and public re-exports |
| `conn.rs` | TLS connection I/O, frame transmission, and `FILE_RESULT` rendezvous |
| `state.rs` | Shared daemon state, session state, pairing state, and synchronization primitives |
| `session.rs` | TCP admission, TLS handshake, reader loop, frame dispatch, pairing, ping, and watchdog |
| `file_transfer.rs` | Outbound queue processing, windowed file sending, chunk encoding, compression, and retry handling |
| `clipboard_sync.rs` | Clipboard watcher and clipboard selection synchronization |
| `util.rs` | Content hashing, file URI conversion, and human-readable size formatting |

## Module Relationships

The implementation is organized around a few core responsibilities:

- **Connection layer (`conn.rs`)** handles the transport-level operations and connection-specific synchronization.
- **State layer (`state.rs`)** provides shared state used across sessions and background tasks.
- **Session layer (`session.rs`)** manages connection admission and protocol-level session behavior.
- **Transfer layer (`file_transfer.rs`)** handles asynchronous outbound file transfers independently of session management.
- **Clipboard layer (`clipboard_sync.rs`)** manages clipboard synchronization without coupling it to the connection lifecycle.
- **Utility layer (`util.rs`)** contains reusable helpers shared by the daemon implementation.

## Visibility and Encapsulation

Cross-module implementation details use `pub(super)` where access from sibling modules is required.

This keeps internal types, fields, and functions scoped to the parent `daemon` module instead of exposing them as part of the crate's public API.

The daemon's public API remains available through the parent module:

```rust
daemon::run(...)
```

Publicly exposed helpers and types are re-exported by `daemon.rs` where needed, so callers do not need to depend directly on the internal module layout.

## Design Goals

- **Separation of concerns:** Each module owns a clearly defined part of the daemon implementation.
- **Minimal behavioral changes:** The refactoring is intended to preserve existing protocol behavior and transfer semantics.
- **Controlled visibility:** Internal cross-module access uses `pub(super)` instead of unnecessarily widening visibility.
- **Stable call sites:** Existing callers continue to use the `daemon` module API without depending on the new internal file structure.
- **Maintainability:** Changes to connection handling, file transfer, or clipboard synchronization can be made in their respective modules.
