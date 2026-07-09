# pi-sandbox
Linux-only sandbox sidecar for Pi, built on the Codex sandbox + proxy crates.

## Install
Requirements:
- Rust toolchain
- `bwrap` (bubblewrap) on `PATH`
- `fd` and `rg` on `PATH` for `find` / `grep`

This repo builds against a local, ignored checkout of OpenAI Codex under
`vendor/openai/codex`. The checkout is created from the pinned stable Codex tag
and patched to allow local Unix sockets in network-sandboxed modes. This keeps
Terraform provider plugin IPC working while preserving network egress controls.

Prepare the Codex vendor checkout before building:
```bash
scripts/prepare_codex_vendor
```

Build and install:
```bash
cargo install --locked --path .
ln -s "$PWD/pi-extension/index.ts" ~/.pi/agent/extensions/pi-sandbox.ts
```

For local verification:
```bash
scripts/prepare_codex_vendor
cargo test
scripts/run_smoke_tests debug
```

To refresh the Codex checkout after changing the patch or tag:
```bash
rm -rf vendor/openai/codex
scripts/prepare_codex_vendor
cargo update -p codex-sandboxing -p codex-linux-sandbox -p codex-network-proxy -p codex-protocol
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
