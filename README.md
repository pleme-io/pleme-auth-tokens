# pleme-auth-tokens

pleme-auth-tokens library

## Installation

```toml
[dependencies]
pleme-auth-tokens = "0.1"
```

## Usage

```rust
use pleme_auth_tokens::{TokenService, TokenConfig};

let service = TokenService::new(TokenConfig::from_env()?);
let token = service.encode(&claims)?;
let decoded = service.decode(&token)?;
```

## Development

This project uses [Nix](https://nixos.org/) for reproducible builds:

```bash
nix develop            # Dev shell with Rust toolchain
nix run .#check-all    # cargo fmt + clippy + test
nix run .#publish      # Publish to crates.io (--dry-run supported)
nix run .#regenerate   # Regenerate Cargo.nix
```

## License

MIT - see [LICENSE](LICENSE) for details.
