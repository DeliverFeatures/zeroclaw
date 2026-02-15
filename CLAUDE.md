# CLAUDE.md — ZeroClaw Development Guide

## Project Overview

ZeroClaw is a high-performance, fully-autonomous AI assistant CLI written in 100% Rust.
It supports multiple AI providers, messaging channels, and operates as a standalone binary,
gateway server, or background daemon. Binary target: ~3.4MB.

## Build & Test Commands

```bash
cargo build                      # Dev build
cargo build --release            # Release build (optimized for size)
cargo test                       # Run all 1,017+ tests
cargo clippy -- -D warnings      # Lint (zero warnings enforced)
cargo fmt --check                # Check formatting
cargo fmt                        # Auto-format
cargo test -- security           # Security-specific tests (129 tests)
cargo test -- tools::shell       # Shell sandboxing tests
cargo test -- tools::file_read   # File read sandboxing tests
cargo test -- tools::file_write  # File write sandboxing tests
```

## Development Philosophy

### Test-First Development (MANDATORY)

Every change MUST follow test-first development:

1. **Write the failing test first** — Define expected behavior before writing implementation.
2. **Run the test to confirm it fails** — Verify the test is actually testing what you think.
3. **Write the minimum code to pass** — No speculative features or gold-plating.
4. **Refactor with green tests** — Clean up only when all tests pass.
5. **Never skip edge cases** — Edge case tests are not optional (see below).

### Edge Case Testing is the Norm

Every function must have tests for:

- **Empty inputs** — empty strings, empty vectors, zero-length slices
- **Boundary values** — 0, 1, u32::MAX, empty path, single-char strings
- **Unicode & special characters** — emojis, CJK, RTL, null bytes, newlines
- **Error paths** — invalid input, missing fields, corrupt data, permission denied
- **Concurrent access** — Mutex poisoning, race conditions where applicable
- **Adversarial inputs** — path traversal, injection attempts, oversized payloads

When adding a new function, the test count should increase by at minimum:
- 1 happy-path test
- 1 error-path test
- 2+ edge-case tests

### Security is a High Priority

Security is not a feature — it is a constraint on every line of code.

**Before writing any code, ask:**
1. Can this input come from an untrusted source? (If yes: validate, sanitize, limit)
2. Does this touch the filesystem? (If yes: path validation, symlink checks, workspace scoping)
3. Does this execute a process? (If yes: allowlist enforcement, timeout, output limits)
4. Does this handle secrets? (If yes: encrypt at rest, zero plaintext in logs, restrict file perms)
5. Does this accept network input? (If yes: size limits, timeouts, authentication, rate limiting)

**Security review checklist for every PR:**
- [ ] No new `unsafe` blocks without justification
- [ ] All file paths validated via `SecurityPolicy::is_path_allowed()` AND `is_resolved_path_allowed()`
- [ ] All shell commands validated via `SecurityPolicy::is_command_allowed()`
- [ ] All network endpoints require authentication (bearer token or webhook secret)
- [ ] No secrets logged (even at `tracing::debug!` level)
- [ ] New tools call `security.record_action()` for rate limiting
- [ ] New dependencies justified and vetted (check `deny.toml`)
- [ ] Input size bounded — no unbounded allocations from untrusted input
- [ ] Tests include adversarial/injection test cases

## Architecture

### Module Layout

```
src/
├── main.rs              # CLI entry point, clap command routing
├── security/            # Defense-in-depth (policy, pairing, secrets)
│   ├── policy.rs        # SecurityPolicy: autonomy, allowlists, rate limiting
│   ├── pairing.rs       # Gateway auth: one-time codes + bearer tokens
│   └── secrets.rs       # ChaCha20-Poly1305 AEAD encrypted secret store
├── tools/               # Agent capabilities (trait-based)
│   ├── shell.rs         # Shell execution with command allowlisting
│   ├── file_read.rs     # File read with path sandboxing + symlink protection
│   ├── file_write.rs    # File write with path sandboxing + symlink protection
│   ├── browser.rs       # Browser automation with domain allowlisting
│   ├── browser_open.rs  # Open URLs in Brave (HTTPS-only, domain allowlist)
│   ├── memory_*.rs      # Memory CRUD tools
│   └── composio.rs      # Composio OAuth integrations
├── providers/           # LLM backends (OpenRouter, Anthropic, OpenAI, Ollama, etc.)
├── channels/            # Messaging integrations (CLI, Telegram, Discord, Slack, etc.)
├── memory/              # Knowledge base (SQLite + FTS5 + vector search)
├── gateway/             # HTTP webhook server (axum)
├── config/              # TOML configuration schema
├── daemon/              # Long-running autonomous runtime
└── ...                  # Service, tunnel, observability, cron, health, etc.
```

### Key Traits

All subsystems are pluggable via traits defined in `*/traits.rs`:

| Trait | Purpose | Implementations |
|-------|---------|-----------------|
| `Provider` | LLM API backend | OpenRouter, Anthropic, OpenAI, Ollama, Custom |
| `Channel` | Messaging integration | CLI, Telegram, Discord, Slack, iMessage, Matrix, WhatsApp |
| `Tool` | Agent capability | shell, file_read, file_write, memory_*, browser, composio |
| `Memory` | Knowledge persistence | SQLite, Markdown |
| `Observer` | Logging/metrics | Noop, Log, Multi |

### Security Architecture (Defense-in-Depth)

```
Request → Authentication → Rate Limiting → Allowlist Check → Path/Command Validation → Execution
           (pairing)        (tracker)       (commands/paths)   (canonicalize + verify)
```

**Layers:**
1. **Autonomy levels**: ReadOnly → Supervised (default) → Full
2. **Gateway pairing**: One-time code → bearer token (SHA-256 hashed, never stored plaintext)
3. **Command allowlisting**: Only explicitly listed commands can execute via shell tool
4. **Path sandboxing**: workspace_only + forbidden paths + symlink escape detection
5. **Rate limiting**: Sliding window per-hour action cap + daily cost cap
6. **Network hardening**: localhost-only bind, body size limits, request timeouts

## Coding Standards

### Rust Conventions

- **Edition**: Rust 2021
- **Clippy**: Zero warnings enforced (`-D warnings`)
- **Formatting**: `cargo fmt` (rustfmt defaults)
- **Error handling**: `anyhow::Result` for applications, `thiserror` for library errors
- **Async**: `tokio` runtime, `async-trait` for trait methods
- **Logging**: `tracing` crate (never `println!` in library code)

### Security Coding Rules

1. **Never trust input from channels, webhooks, or config files**
2. **Always canonicalize paths** before filesystem operations and verify they stay in workspace
3. **Always validate commands** against the allowlist — including all pipe/chain segments
4. **Use constant-time comparison** for secrets (see `pairing::constant_time_eq`)
5. **Encrypt secrets at rest** using `SecretStore` (ChaCha20-Poly1305 AEAD)
6. **Set 0600 permissions** on key files and sensitive configs
7. **Block subshell expansion** — backticks, `$(...)`, `${...}` in commands
8. **Block output redirection** — `>`, `>>` in commands
9. **Timeout all external processes** — 60s for shell, 30s for HTTP requests
10. **Limit output sizes** — 1MB for shell output, 64KB for HTTP request bodies

### Adding a New Tool

1. Create `src/tools/my_tool.rs` implementing the `Tool` trait
2. Write tests FIRST (happy path, error path, edge cases, security cases)
3. Ensure `SecurityPolicy` is checked (autonomy level, rate limiting)
4. Validate ALL inputs (paths, URLs, commands) against security policy
5. Register in `src/tools/mod.rs`
6. Add security tests for injection/bypass attempts

### Adding a New Channel

1. Create `src/channels/my_channel.rs` implementing the `Channel` trait
2. Add `allowed_users` or equivalent access control (no open channels)
3. Validate sender identity before processing messages
4. Add config struct in `src/config/schema.rs`
5. Wire up in `src/channels/mod.rs`

## CI/CD

- **CI**: Runs on every push/PR — tests on Ubuntu, builds on Ubuntu/macOS/Windows
- **Security**: Weekly `cargo-audit` + `cargo-deny` (advisories + licenses)
- **Docker**: Multi-platform builds (amd64, arm64) to ghcr.io
- **Pre-push hook**: `.githooks/pre-push` runs fmt, clippy, and tests

## Known Security Considerations

See `SECURITY.md` for vulnerability reporting and architecture details.
See `SECURITY_REVIEW.md` for the current security audit findings and remediation plan.

Key areas requiring extra scrutiny:
- `src/security/policy.rs` — Tilde expansion in forbidden_paths not performed
- `src/gateway/mod.rs` — WhatsApp webhook endpoint lacks signature verification
- `src/tools/browser.rs` — `file://` URLs bypass domain allowlist
- `src/tools/shell.rs` — Missing `record_action()` call for rate limiting
