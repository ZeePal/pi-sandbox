# pi-sandbox
Linux-only sandbox sidecar for Pi, built on the Codex sandbox + proxy crates.

## Install
Requirements:
- Rust toolchain
- `bwrap` (bubblewrap) on `PATH`
- `fd` and `rg` on `PATH` for `find` / `grep`

Build and install:
```bash
cargo install --locked --path .
ln -s "$PWD/pi-extension/index.ts" ~/.pi/agent/extensions/pi-sandbox.ts
```

## Configure
Config can live in either of these files:
- user: `~/.pi/agent/sandbox.json`
- project: `<project>/.pi/sandbox.json`

Project config overrides user config.

Minimal example:
```json
{
  "fs": "write",               // write (default), readonly or unrestricted
  "net": "none",               // none (default), restricted or unrestricted
  "network_proxy": {
    "allow": [                 // default: []
        "github.com",
        "*.github.com"
    ],
    "deny": ["example.com"],   // default: []
    "allow_local": false       // default: false
  }
}
```

## Architecture
- See: [ARCHITECTURE.md](ARCHITECTURE.md)

## Notes
- session approvals are stored under `~/.pi/agent/sandbox-sessions/`
