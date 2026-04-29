# Agent guidance for lmtp-dkim

This document is for AI agents and automated tools working on this repository.
Humans: see [README.md](README.md).

## Project purpose

`lmtp-dkim` is an async Rust email signing and verification service. It
listens for LMTP connections and:

- **Inbound**: validates DKIM signatures, validates the ARC chain, adds an
  `Authentication-Results` header, ARC-seals the message, and forwards it
  downstream via LMTP.
- **Outbound**: DKIM-signs the message and forwards it downstream via
  LMTP/SMTP.

## Repository layout

```
Cargo.toml                      workspace root
crates/
  email-primitives/             shared types: address, header, message
  lmtp/                         async LMTP protocol (RFC 2033)
  dkim/                         DKIM signing + verification (RFC 6376, RFC 8463)
  arc/                          ARC chain sealing + validation (RFC 8617)
  service/                      binary: inbound and outbound pipelines
.github/workflows/ci.yml        CI: lint, test, build
.pre-commit-config.yaml         pre-commit hooks
renovate.json                   Renovate dependency update config
```

All implementations are `todo!()` stubs with comprehensive documentation
explaining what each function must do and which RFC section governs it.
Filling in those stubs is the primary work remaining.

## Essential commands

```sh
cargo check --workspace --all-targets   # fast type-check
cargo nextest run --workspace           # compile and run tests
cargo clippy --workspace --all-targets  # lint
cargo fmt --check                       # formatting check
cargo fmt                               # fix formatting
```

Install cargo-nextest if you don't have it:

```sh
cargo install cargo-nextest --locked
```

Run pre-commit locally:

```sh
pre-commit run --all-files
```

## Implementation order

The natural implementation order follows the dependency graph:

01. **`email-primitives`**: parse addresses (`address.rs`), header fields
    (`header.rs`), and full messages (`message.rs`). Use `winnow` for
    parsing. These are the foundation everything else builds on.

02. **`lmtp/codec`**: implement `CommandCodec` (CRLF framing) and
    `DataCodec` (dot-unstuffing, `\r\n.\r\n` terminator).

03. **`lmtp/session`**: fill in the session state machine transitions in
    `handle_command` and `receive_data`.

04. **`lmtp/server`**: wire `run_session` to use `Framed` with the codecs
    and drive the session.

05. **`dkim/tag_list`**: implement the `k=v; k=v` tag-list parser/serialiser.

06. **`dkim/signature`**: implement `DkimSignature::parse` and serialisation.

07. **`dkim/canonicalize`**: implement the four canonicalization paths
    (header×{simple,relaxed}, body×{simple,relaxed}).

08. **`dkim/key`**: wrap `ring` key types; implement `PrivateKey::sign` and
    `PublicKey::verify`.

09. **`dkim/dns`**: implement `DkimResolver::lookup` using `hickory-resolver`.

10. **`dkim/sign`**: implement `Signer::sign` end-to-end.

11. **`dkim/verify`**: implement `Verifier::verify` end-to-end.

12. **`arc/auth_results`**: implement `AuthResultsValue::parse` (RFC 7601 §2.2).

13. **`arc/headers`**: implement parsing and serialisation for `ArcSeal`,
    `ArcMessageSignature`, `AuthenticationResults`.

14. **`arc/chain`**: implement `ChainValidator::validate` (RFC 8617 §6).

15. **`arc/seal`**: implement `ArcSigner::seal` (RFC 8617 §5).

16. **`service/inbound`** + **`service/outbound`**: wire the above into the
    `MessageHandler` implementations and `run()` entry points.

## Key invariants

- **CRLF everywhere**: messages are stored and processed with `\r\n` line
  endings throughout. Normalise at boundaries; never silently accept bare
  `\n` in signing/hashing code.

- **Bottom-up header selection for DKIM**: when the `h=` tag lists a header
  name that appears multiple times, headers are consumed bottom-up
  (RFC 6376 §5.4.2). The data structure in `Headers` preserves insertion
  order to support this.

- **`b=` empty during signing**: the DKIM-Signature header's own hash input
  uses the tag-list with `b=` set to an empty string (RFC 6376 §3.7).

- **ARC header insertion order**: the three new ARC headers must be prepended
  in the order `ARC-Seal`, `ARC-Message-Signature`,
  `ARC-Authentication-Results` — outermost (highest-instance) first
  (RFC 8617 §5.1). Reading the headers top-to-bottom gives descending
  instance numbers.

- **ARC seal hash input order**: the AS hash input is AAR(1..N) || AMS(1..N)
  || AS(1..N-1) || AS(N, b=empty). See RFC 8617 §5.1.1 and the comment in
  `arc/src/seal.rs`.

- **DNS failure mode**: distinguish `temperror` (SERVFAIL/timeout → retry)
  from `permerror` (NXDOMAIN/no-record → permanent failure). See
  `dkim/src/dns.rs` and RFC 6376 §3.9.

- **ARC instance limit**: if adding a new ARC set would set `i > 50`, the
  service must not add ARC headers (RFC 8617 §5.1.1.3).

## Canonical RFCs

The doc comments in each source file cite specific RFC sections. When
implementing a function, read the cited section before writing code.
The RFCs are the authoritative specification; do not interpret the stub
comments as complete specifications.

| Crate              | Primary RFC(s)               |
| ------------------ | ---------------------------- |
| `email-primitives` | RFC 5321, RFC 5322           |
| `lmtp`             | RFC 2033, RFC 5321           |
| `dkim`             | RFC 6376, RFC 8301, RFC 8463 |
| `arc`              | RFC 8617, RFC 7601           |

## Testing strategy

**No tests are written yet.** When adding tests, follow these two classes:

### Unit tests (in `#[cfg(test)]` modules within each crate)

Each unit test validates one specific, self-contained behaviour of a
function, with a comment citing the RFC section that mandates it. Examples:

- `test_relaxed_header_lowercase` → RFC 6376 §3.4.2 step 1
- `test_body_simple_trailing_crlf` → RFC 6376 §3.4.3
- `test_tag_list_reject_duplicate` → RFC 6376 §3.2 rule 5
- `test_domain_case_insensitive` → RFC 5321 §2.3.5
- `test_lmtp_helo_rejected` → RFC 2033 §4.1

### Integration tests (in `crates/*/tests/` or `tests/` at workspace root)

Integration tests verify each stated RFC requirement as a named test that
cites the RFC. Additional layers:

- **Example tests**: use the test vectors in the RFCs themselves where they
  exist (e.g. RFC 6376 Appendix A contains a complete DKIM example with a
  known message, headers, and expected `b=` value).

- **Property-based tests** (`proptest` or `bolero`): generate arbitrary
  inputs and assert invariants (e.g. canonicalize(canonicalize(x)) ==
  canonicalize(x); sign then verify always returns `pass`).

- **Mutation tests** (`cargo-mutants`): exercise the test suite against
  mutations to catch gaps in coverage of critical paths like signature
  verification and chain validation.

A test module pattern to adopt:

```rust
#[cfg(test)]
mod rfc6376 {
    /// RFC 6376 §3.4.2: relaxed header canonicalization lowercases the name.
    #[test]
    fn relaxed_header_lowercase() { ... }

    /// RFC 6376 §3.4.3: simple body canonicalization strips trailing empty
    /// lines and appends exactly one CRLF.
    #[test]
    fn simple_body_trailing_crlf() { ... }
}
```

## Code style

- No comments unless the WHY is non-obvious (hidden constraint, RFC quirk,
  workaround). The existing doc comments on stubs are intentional — they
  record what the function must do; remove or replace them once implemented.
- No unnecessary error handling for internal callers; validate at boundaries.
- Use `todo!("explanation")` strings in stubs; the explanation should cite
  the algorithm or RFC section, not just say "implement this".
- Keep types close to the RFC vocabulary. If the RFC names a concept, use
  that name.

## Pre-commit hooks

The pre-commit configuration runs:

- Standard file checks (trailing whitespace, YAML/TOML validity, etc.)
- `cargo fmt` — formatting (fails if code is not formatted)
- `cargo clippy` — linting (run via a Docker container with pinned Rust)
- `actionlint` — GitHub Actions workflow linting
- `check-github-workflows` and `check-renovate` — JSON schema validation
- `renovate-config-validator --strict` — Renovate config validation
- `editorconfig-checker` — EditorConfig compliance

Run `pre-commit run --all-files` to check everything locally.

## Dependency update policy

Renovate is configured to auto-merge minor, patch, and digest updates.
Major updates are labelled and auto-merged after any other pending updates.
Pre-commit hook versions are also managed by Renovate.
