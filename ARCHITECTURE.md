# ARCHITECTURE
`pi-sandbox` is a **Pi-facing security adapter** around OpenAI Codex's Linux sandboxing components. It does **not** try to re-implement bubblewrap, seccomp, or proxy-routing itself; instead it translates Pi tool calls and Pi UI approvals into the Codex sandbox + network-proxy model.

> Credit: this repo builds on OpenAI/Codex's open-source crates:
> - [`codex-sandboxing`](https://github.com/openai/codex/tree/main/codex-rs/sandboxing)
> - [`codex-linux-sandbox`](https://github.com/openai/codex/tree/main/codex-rs/linux-sandbox)
> - [`codex-network-proxy`](https://github.com/openai/codex/tree/main/codex-rs/network-proxy)
> - [`codex-protocol`](https://github.com/openai/codex/tree/main/codex-rs/protocol)
>
> This doc focuses on **how this repo wraps them for Pi**, especially from a security point of view.

## The short version
1. **Pi extension** (`pi-extension/index.ts`) replaces Pi's normal tools with wrapped versions.
2. Wrapped tools spawn the **`pi-sandbox` sidecar** over JSON/JSONL.
3. The Rust sidecar maps Pi's `fs` / `net` choices into a Codex `PermissionProfile`.
4. For sandboxed runs, the sidecar **self-invokes as `codex-linux-sandbox`** and hands off to Codex's Linux helper.
5. For `net=restricted`, the sidecar also starts **Codex's local managed proxy**, injects proxy env vars, and routes traffic through policy checks + user approval.
6. File tools (`read`, `write`, `edit`, `ls`, `find`, `grep`) are re-run **inside** the sandbox. They use `net=none` unless networking is already `unrestricted`, and readonly tools (`read`, `ls`, `find`, `grep`) use `fs=readonly` unless the session is already `fs=unrestricted`.
7. Only `fs=unrestricted` **and** `net=unrestricted` trigger full direct passthrough.

## Main flow
```text
+--------------------------------------------------------------------------------+
|                                 Pi session                                     |
|                                                                                |
|  Pi                                                                            |
|     |                                                                          |
|     v                                                                          |
|  pi-extension/index.ts                                                         |
|     - replaces tool implementations                                            |
|     - owns UI prompts and status footer                                        |
|     - chooses fs/net mode per session                                          |
|     |                                                                          |
|     v                                                                          |
|  pi-sandbox (Rust sidecar)                                                     |
|     - loads ~/.pi/agent/sandbox.json and project .pi/sandbox.json              |
|     - maps Pi modes -> Codex PermissionProfile                                 |
|     - starts managed proxy when net=restricted                                 |
|     - self-invokes as codex-linux-sandbox                                      |
|     |                                                                          |
|     +--> codex-network-proxy (restricted net only)                             |
|     |      - allow / deny / ask                                                |
|     |      - optional allow-once / session / persistent policy                 |
|     |                                                                          |
|     +--> codex-linux-sandbox                                                   |
|            - bubblewrap filesystem view                                        |
|            - namespaces + seccomp + no_new_privs                               |
|            - runs bash or internal tools (read/write/etc) inside the sandbox   |
|                                                                                |
+--------------------------------------------------------------------------------+
```

## Trust boundaries
### 1) Pi UI / tool boundary
The extension owns:
- current `fs` / `net` mode
- session key derivation
- user-visible approval prompts
- status/footer updates

### 2) Sidecar policy boundary
The Rust binary owns:
- config loading and merge order (`~/.pi/agent/sandbox.json` then project `.pi/sandbox.json`)
- sandbox config loading (`fs`, `net`, `network_proxy`)
- session / persistent allowlists
- conversion from Pi modes to Codex permission profiles
- spawning the Codex helper and managed proxy

### 3) Kernel-enforced sandbox boundary
Codex's helper owns the hard part:
- bubblewrap filesystem view
- namespace isolation
- seccomp / `no_new_privs`
- proxy-only network routing when restricted networking is enabled

## Security properties that matter here
- **Filesystem policy is not just advisory.** In sandboxed mode, tools run in the Codex Linux sandbox.
- **Network policy is not just env-var based.** In `restricted` mode, traffic is intended to flow through Codex's managed proxy, with allow/deny checks and optional approvals.
- **Inherited proxy variables are cleared first.** `pi-sandbox` removes existing proxy env vars before injecting its own managed proxy settings.
- **Approvals are deduped.** Concurrent requests for the same host/protocol/port collapse into one approval prompt.
- **Approvals can persist.** `allow once` stays in-memory, `allow for session` lands under `~/.pi/agent/sandbox-sessions/`, and `always allow` updates sandbox config.
- **Write mode is still scoped.** `write` maps to workspace-write semantics, not full-disk write. If `.pi` exists in the runtime cwd, this repo adds an explicit read-only rule for it.
- **Internal file tools run with the narrowest practical sandbox.** Local file tools avoid the managed proxy by using `net=none` unless networking is already fully unrestricted, and readonly tools drop to `fs=readonly` unless filesystem access is already fully unrestricted.
- **Global wildcard hosts are rejected.** Config validation blocks `"*"` as an allow/deny pattern.
- **Full bypass is explicit.** Direct passthrough only happens when both filesystem and networking are set to `unrestricted`.

## Common modes
| Mode                          | Filesystem                      | Networking            | What actually happens        |
| ---                           | ---                             | ---                   | ---                          |
| `readonly + none`             | whole FS read-only              | isolated / no network | safest inspect-only mode     |
| `readonly + restricted`       | whole FS read-only              | proxy-only egress     | read/query with approvals    |
| `write + none`                | workspace write, rest read-only | isolated / no network | edit locally, no egress      |
| `write + restricted`          | workspace write, rest read-only | proxy-only egress     | normal authoring mode        |
| `unrestricted + unrestricted` | no FS sandbox                   | no net sandbox        | direct Pi/original tool path |

## Repo map
- `pi-extension/index.ts` - Pi integration, tool wrapping, JSONL approval UI
- `src/cli.rs` - CLI entrypoints, JSONL tool mode, helper handoff
- `src/sandbox.rs` - permission mapping, proxy startup, helper spawning
- `src/approval.rs` - prompt/external approval brokers and JSONL framing
- `src/config.rs` - config merge, validation, policy persistence
- `src/internal_tools.rs` - file tools that are executed inside the sandbox
