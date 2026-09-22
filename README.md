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
Sandbox config lives under `ZeePal.sandbox` in either settings file:
- user: `~/.pi/agent/settings.json`
- project: `<project>/.pi/settings.json`

Trusted project config overrides user config.

Minimal example:
```jsonc
{
  "ZeePal": {
    "sandbox": {
      "fs": "write",               // write (default), readonly or unrestricted
      "net": "none",               // none (default), restricted or unrestricted
      "network_proxy": {
        "allow": [                  // default: []
          "github.com",
          "*.github.com"
        ],
        "deny": ["example.com"],    // default: []
        "allow_local": false        // default: false
      }
    }
  }
}
```

Startup flags override both settings files for the Pi process:
```bash
pi --sandbox-fs readonly --sandbox-net restricted
```

The flags accept the same canonical values as their equivalent config fields:
- `--sandbox-fs`: `readonly`, `write`, or `unrestricted`
- `--sandbox-net`: `none`, `restricted`, or `unrestricted`

The aliases used by `/fs` and `/net` are also accepted: `r`, `w`, or `u` for
filesystem mode; and `n`, `r`, `u`, `s`, or `sandboxed` for network mode.

## Architecture
- See: [ARCHITECTURE.md](ARCHITECTURE.md)

## Notes
- session approvals are stored under `~/.pi/agent/sandbox-sessions/`
- when `AGENTWRAP_SANDBOX=true`, the trusted outer sandbox supplies IPC namespace isolation, so the inner Bubblewrap invocation does not request a redundant IPC namespace
