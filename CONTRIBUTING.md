# Contributing to rustguac

## Development Setup

```bash
# Clone the repo
git clone https://github.com/sol1/rustguac.git
cd rustguac

# Install dependencies and build guacd
./dev.sh

# Run in development mode
cargo run -- serve
```

## Code Style

Rust formatting and linting are enforced:

```bash
cargo fmt          # auto-format code
cargo clippy       # lint for common mistakes
cargo fmt --check  # verify formatting in CI
```

Fix any clippy warnings before submitting a PR. The project follows standard
Rust conventions: snake_case functions, CamelCase types, `//` line comments
(never `/* */` block comments), `//!` module doc comments at file top.

## Testing

```bash
cargo test                              # unit and integration tests
./tests/test_browser_session.sh         # browser session smoke test
```

The browser test spawns Xvnc + Chromium, takes a screenshot with xwd/ImageMagick,
and asserts non-black pixels. Requires Xvnc and Chromium installed on the system.

## PR Process

1. Fork the repo and create a feature branch (`git checkout -b feat/my-feature`).
2. Make changes following the code style above.
3. Run `cargo fmt`, `cargo clippy`, and `cargo test`.
4. Ensure the browser session test passes if you touched session or browser code.
5. Update `CLAUDE.md` if you changed architecture, config keys, or session types.
6. Open a PR against `main` with a clear title and description.

## Adding guacamole-server Patches

The `patches/` directory contains patches applied to guacamole-server before
building. To add a new patch:

1. Edit `../guacamole-server` source code.
2. Export the diff: `git diff > patches/NNN-description.patch`.
3. Number patches sequentially (001-, 002-, etc.).
4. All build scripts (`dev.sh`, `install.sh`, `Dockerfile`) apply patches automatically.
5. Document what the patch fixes in `patches/README.md`.

## Architecture Overview

See [docs/overview.md](docs/overview.md) for a high-level overview of the
architecture, session lifecycle, and protocol flow.
