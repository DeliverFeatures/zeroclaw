# Security Review — ZeroClaw

**Date**: 2026-02-15
**Scope**: Full codebase security audit with focus on input validation, authentication,
authorization, cryptographic practices, and injection vulnerabilities.

---

## Summary

ZeroClaw has a strong security foundation: defense-in-depth architecture, command
allowlisting, path sandboxing with symlink protection, encrypted secret storage
(ChaCha20-Poly1305), gateway pairing authentication, and rate limiting. The codebase
includes 129+ dedicated security tests.

However, this review identified **7 HIGH**, **7 MEDIUM**, and **4 LOW** severity issues
that should be addressed.

---

## HIGH Severity

### H1: ShellTool does not call `record_action()` — bypasses rate limiting

**File**: `src/tools/shell.rs:47-111`

The `ShellTool::execute()` method validates commands against the allowlist but never
calls `self.security.record_action()`. By contrast, `BrowserTool` and `BrowserOpenTool`
both correctly call `record_action()`. This means an agent in `Full` autonomy mode
could execute unlimited shell commands per hour, bypassing the
`max_actions_per_hour` cap.

**Remediation**: Add `record_action()` check at the top of `ShellTool::execute()`,
after the `is_command_allowed` check and before spawning the process.

```rust
if !self.security.record_action() {
    return Ok(ToolResult {
        success: false,
        output: String::new(),
        error: Some("Action blocked: rate limit exceeded".into()),
    });
}
```

**Test**: Add test `shell_blocks_when_rate_limited` with `max_actions_per_hour: 0`.

---

### H2: WhatsApp webhook endpoint has no authentication

**File**: `src/gateway/mod.rs:352-424`

The `handle_whatsapp_message` handler does not check bearer token authentication.
Unlike `handle_webhook` (line 243) which validates pairing tokens, the WhatsApp
endpoint accepts any POST request. An attacker who discovers the endpoint URL
can send arbitrary forged messages that are processed by the LLM.

**Remediation**: Either:
- (a) Add bearer token authentication to the WhatsApp endpoint (matching `handle_webhook`), or
- (b) Implement Meta's HMAC-SHA256 signature verification using the app secret
  (the `X-Hub-Signature-256` header), or
- (c) Both (recommended — defense-in-depth).

**Test**: Add test that POST to `/whatsapp` without authentication returns 401.

---

### H3: No HMAC signature verification for WhatsApp webhook payloads

**File**: `src/channels/whatsapp.rs`, `src/gateway/mod.rs:352`

Meta signs all webhook payloads with HMAC-SHA256 using the app secret
(`X-Hub-Signature-256` header). The code does not verify these signatures.
Without this, any HTTP client can send fake WhatsApp messages.

**Remediation**: Verify the `X-Hub-Signature-256` header against the raw request
body using the WhatsApp app secret:

```rust
use sha2::Sha256;
use hmac::{Hmac, Mac};

fn verify_meta_signature(body: &[u8], signature_header: &str, app_secret: &str) -> bool {
    let Some(hex_sig) = signature_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}
```

**Test**: Add tests with valid and invalid HMAC signatures, missing header, and
malformed header values.

---

### H4: Forbidden paths with tilde (`~`) not expanded — bypass possible

**File**: `src/security/policy.rs:248-253`

The forbidden paths list includes `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config`.
The `is_path_allowed` function uses `path.starts_with(forbidden)` which only
matches if the input path also literally starts with `~`. An expanded path like
`/home/user/.ssh/id_rsa` would NOT match `~/.ssh` and bypasses the check.

This matters when `workspace_only: false` — the tilde-based forbidden paths
provide no protection because paths from tools/channels are never tilde-prefixed.

**Remediation**: Expand `~` to the actual home directory at policy construction
time in `SecurityPolicy::default()` and `SecurityPolicy::from_config()`:

```rust
fn expand_tilde(paths: &[String]) -> Vec<String> {
    let home = dirs::home_dir().unwrap_or_default();
    paths.iter().map(|p| {
        if let Some(rest) = p.strip_prefix("~/") {
            home.join(rest).to_string_lossy().to_string()
        } else {
            p.clone()
        }
    }).collect()
}
```

**Test**: Add test that `/home/<user>/.ssh/id_rsa` is blocked when `workspace_only: false`.

---

### H5: Browser tool `file://` URLs bypass domain allowlist

**File**: `src/tools/browser.rs:132-135`

The `BrowserTool::validate_url()` method returns `Ok(())` for any `file://` URL
without checking the domain allowlist or validating the path. This allows reading
arbitrary local files through the browser tool:

```
file:///etc/passwd
file:///home/user/.ssh/id_rsa
```

**Remediation**: Remove `file://` URL support entirely, or restrict it to paths
within the workspace directory using `SecurityPolicy::is_path_allowed()` and
`is_resolved_path_allowed()`.

```rust
if url.starts_with("file://") {
    // Block file:// URLs in production — only allow in tests
    anyhow::bail!("file:// URLs are not allowed for security reasons");
}
```

**Test**: Add test that `file:///etc/passwd` is rejected.

---

### H6: Screenshot path not validated in BrowserTool

**File**: `src/tools/browser.rs:271-272`

The `Screenshot` action accepts a `path` parameter that is passed directly to
`agent-browser` without any validation against the `SecurityPolicy`. An attacker
could save screenshots to arbitrary paths outside the workspace:

```json
{"action": "screenshot", "path": "/etc/cron.d/malicious"}
```

**Remediation**: Validate the screenshot path using `SecurityPolicy::is_path_allowed()`
and `is_resolved_path_allowed()` before passing it to the browser CLI. If no path
is provided, default to a workspace-relative location.

**Test**: Add tests for path traversal via screenshot path (e.g., `../../etc/evil`).

---

### H7: `is_path_allowed` returns `true` for empty path

**File**: `src/security/policy.rs:232`

An empty string passes all validation in `is_path_allowed`:
- No null bytes ✓
- No `..` ✓
- Not absolute ✓
- Doesn't match forbidden paths ✓

While downstream code would fail on an empty path, a defense-in-depth approach
should reject empty paths at the policy level.

**Remediation**: Add an empty path check at the top of `is_path_allowed`:

```rust
if path.is_empty() {
    return false;
}
```

**Test**: Update `empty_path_allowed` test to assert `!p.is_path_allowed("")`.

---

## MEDIUM Severity

### M1: Windows `icacls` argument injection risk

**File**: `src/security/secrets.rs:195-206`

The `build_windows_icacls_grant_arg` function takes a username from the
`USERNAME` environment variable and formats it into `{username}:F` which is
passed as a command argument to `icacls`. While `.arg()` prevents shell
expansion, a malicious `USERNAME` value containing spaces or special characters
could cause unexpected `icacls` behavior.

**Remediation**: Validate that the username contains only alphanumeric characters,
dots, hyphens, underscores, and backslashes (for domain\user format):

```rust
fn build_windows_icacls_grant_arg(username: &str) -> Option<String> {
    let normalized = username.trim();
    if normalized.is_empty() {
        return None;
    }
    // Reject suspicious characters
    if !normalized.chars().all(|c| c.is_alphanumeric() || ".-_\\".contains(c)) {
        return None;
    }
    Some(format!("{normalized}:F"))
}
```

**Test**: Add tests for usernames with `&`, `|`, `>`, spaces.

---

### M2: Config file may store API keys in plaintext without restricted permissions

**File**: `src/config/schema.rs:754-758`

`Config::save()` writes the entire config to `config.toml` including `api_key`.
If `secrets.encrypt = false` or encryption hasn't been applied yet, the API key
is stored in plaintext. The file is written with default permissions (respects
umask, typically 0644 — world-readable).

**Remediation**:
1. Set 0600 permissions on `config.toml` after writing (like the secret key file).
2. Warn if `api_key` is present in plaintext and `secrets.encrypt = true`.

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&self.config_path, fs::Permissions::from_mode(0o600))?;
}
```

**Test**: Add test that config file has 0600 permissions after save.

---

### M3: No input length limit on webhook message content

**File**: `src/gateway/mod.rs:290`

The HTTP body limit is 64KB, but the `message` field within the JSON is not
separately validated. A near-64KB prompt forwarded to an LLM provider could be
expensive. The `max_cost_per_day_cents` cap exists but only tracks action count,
not actual API cost.

**Remediation**: Add a configurable maximum message length (e.g., 4096 characters)
and reject messages exceeding it:

```rust
const MAX_MESSAGE_LENGTH: usize = 4096;
if webhook_body.message.len() > MAX_MESSAGE_LENGTH {
    return (StatusCode::BAD_REQUEST, Json(json!({"error": "Message too long"})));
}
```

**Test**: Add test with an oversized message.

---

### M4: Pairing code is only 6 digits — brute-forceable over time

**File**: `src/security/pairing.rs:177`

The pairing code has 1,000,000 possible values. With 5 attempts before a
5-minute lockout, an attacker can try 60 codes/hour (5 per 5-min window).
After ~694 hours (~29 days) of continuous automated attempts, they'd have a
50% chance of guessing the code.

**Remediation**: Increase to 8 digits (100M possibilities) or use an
alphanumeric code (36^6 = ~2.2 billion possibilities). Alternatively, add
progressive lockout (double the lockout duration after each burst).

**Test**: Verify that codes are at least 8 characters and contain mixed characters.

---

### M5: Bearer token uses UUID v4 — lower entropy than dedicated CSPRNG

**File**: `src/security/pairing.rs:193`

Bearer tokens are generated as `zc_{uuid_v4_simple}`. UUID v4 has ~122 bits
of entropy (128 bits minus 6 fixed version/variant bits). While adequate for
most purposes, security tokens should ideally use 256 bits from a direct CSPRNG.

**Remediation**: Use `ChaCha20Poly1305::generate_key(&mut OsRng)` (already
available in the crate) or generate 32 random bytes directly:

```rust
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("zc_{}", hex::encode(bytes))
}
```

**Test**: Verify token length is at least 64 hex chars after the `zc_` prefix.

---

### M6: No CORS headers on gateway

**File**: `src/gateway/mod.rs`

The gateway does not set CORS headers. If accidentally exposed to the internet
(e.g., `allow_public_bind = true`), a malicious website could make cross-origin
requests to the gateway from a user's browser.

**Remediation**: Add restrictive CORS headers via `tower-http::cors`:

```rust
use tower_http::cors::{CorsLayer, AllowOrigin};
let cors = CorsLayer::new().allow_origin(AllowOrigin::exact("null".parse().unwrap()));
```

Or simpler: deny all cross-origin requests by not setting any CORS headers
(the browser's same-origin policy blocks them by default — but preflight
OPTIONS requests should return 403).

**Test**: Add test that cross-origin requests are rejected.

---

### M7: `FileWriteTool` creates parent directories before validating resolved path

**File**: `src/tools/file_write.rs:68-69`

`create_dir_all(parent)` is called BEFORE the resolved-path check
(`is_resolved_path_allowed`). An attacker could use this to create
directory structures outside the workspace if the parent path resolves
outside the workspace after symlink resolution.

**Remediation**: Move `create_dir_all` to AFTER the resolved-path check,
or validate the path before creating directories.

**Test**: Add test that directory creation outside workspace is blocked.

---

## LOW Severity

### L1: No structured security audit trail

Gateway requests are logged at the tracing level, but there's no dedicated
structured audit log for security-relevant events (authentication failures,
blocked commands, path traversal attempts, rate limit hits).

**Remediation**: Add a dedicated `security_audit` tracing target with structured
fields (event_type, source_ip, path, command, result).

---

### L2: No token revocation mechanism

Once a bearer token is issued via `/pair`, it cannot be revoked without manually
editing `config.toml` and restarting the gateway.

**Remediation**: Add a `DELETE /pair` or `POST /revoke` endpoint that requires
the bearer token being revoked (self-revocation).

---

### L3: Memory content not sanitized for prompt injection

Content stored in SQLite memory via `memory_store` is retrieved verbatim by
`memory_recall` and injected into agent context. Malicious stored content could
manipulate agent behavior.

**Remediation**: Consider adding a metadata flag to distinguish user-authored vs.
agent-authored memories, and apply appropriate framing/escaping when injecting
recalled memories into prompts.

---

### L4: `..` check produces false positives on legitimate filenames

**File**: `src/security/policy.rs:239`

The path traversal check rejects any path containing `..` as a substring,
including legitimate filenames like `my..file.txt` or `version..2.tar.gz`.

**Remediation**: Replace the substring check with a component-level check:

```rust
use std::path::Component;
if Path::new(path).components().any(|c| c == Component::ParentDir) {
    return false;
}
```

**Test**: Add test that `my..file.txt` is allowed while `../escape` is blocked.

---

## Remediation Priority Plan

### Phase 1 — Critical (address immediately)

| Issue | Fix | Effort | Files |
|-------|-----|--------|-------|
| **H1** | Add `record_action()` to ShellTool | Small | `tools/shell.rs` |
| **H2** | Add auth to WhatsApp webhook | Medium | `gateway/mod.rs` |
| **H5** | Block `file://` URLs in BrowserTool | Small | `tools/browser.rs` |
| **H7** | Reject empty paths in `is_path_allowed` | Small | `security/policy.rs` |

### Phase 2 — Important (address within 1 sprint)

| Issue | Fix | Effort | Files |
|-------|-----|--------|-------|
| **H3** | Add HMAC signature verification | Medium | `gateway/mod.rs`, `channels/whatsapp.rs` |
| **H4** | Expand tilde in forbidden paths | Medium | `security/policy.rs` |
| **H6** | Validate screenshot paths | Small | `tools/browser.rs` |
| **M2** | Set 0600 on config.toml | Small | `config/schema.rs` |
| **M7** | Reorder dir creation after path check | Small | `tools/file_write.rs` |

### Phase 3 — Hardening (address within 1 quarter)

| Issue | Fix | Effort | Files |
|-------|-----|--------|-------|
| **M1** | Sanitize Windows username for icacls | Small | `security/secrets.rs` |
| **M3** | Add message length limit | Small | `gateway/mod.rs` |
| **M4** | Increase pairing code entropy | Small | `security/pairing.rs` |
| **M5** | Use direct CSPRNG for bearer tokens | Small | `security/pairing.rs` |
| **M6** | Add CORS restrictions | Medium | `gateway/mod.rs` |
| **L1-L4** | Audit logging, token revocation, etc. | Medium-Large | Multiple |

---

## Positive Findings

The following security practices are well-implemented and should be maintained:

1. **ChaCha20-Poly1305 AEAD** for secret encryption with random nonces
2. **Symlink escape detection** via canonicalization in file_read and file_write
3. **Null byte injection blocking** in path validation
4. **Constant-time comparison** for pairing codes and webhook secrets
5. **Bearer token hashing** (SHA-256) — plaintext never stored
6. **Command allowlisting** with subshell/expansion/redirect blocking
7. **Distroless nonroot container** (UID 65534, no shell)
8. **Gateway localhost-only binding** by default with public bind refusal
9. **Request body limits** (64KB) and timeouts (30s) against DoS
10. **Brute-force lockout** on pairing (5 attempts → 5-min lock)
11. **Comprehensive test coverage** (1,017+ tests, 129 security-specific)
12. **Dependency auditing** via `cargo-audit` and `cargo-deny` in CI
