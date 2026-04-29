# lmtp-dkim

An async Rust service that sits in front of a mail store and a mail relay,
adding DKIM signatures and ARC seals to email.

## What it does

Email authentication relies on cryptographic signatures that travel with the
message. This service adds and verifies those signatures at two points in
the mail flow:

### Inbound mode — validate and ARC-seal

```
Internet MTA  ──LMTP──▶  lmtp-dkim  ──LMTP──▶  mailstore / next hop
                              │
                              ├─ verify all DKIM-Signature headers (RFC 6376)
                              ├─ validate existing ARC chain (RFC 8617)
                              ├─ evaluate SPF result (RFC 7208)
                              ├─ add Authentication-Results header (RFC 7601)
                              └─ ARC-seal: prepend AAR + AMS + AS headers
```

Mail arriving from the Internet may have been handled by mailing list servers
or forwarding services that broke the original DKIM signatures.
ARC ([RFC 8617]) lets each intermediary sign a record of the authentication
state it observed, so that your mailstore can still reason about the original
sender's reputation.

### Outbound mode — DKIM-sign

```
MUA / submission  ──LMTP──▶  lmtp-dkim  ──LMTP──▶  Internet relay
                                   │
                                   └─ DKIM-sign per sending domain (RFC 6376)
```

Mail submitted by users is signed with the domain's DKIM private key before
it reaches the relay. The signing domain is derived from the `From:` header.

## Architecture

The workspace is split into focused crates with minimal cross-dependencies:

```
crates/
├── email-primitives/   Core types: addresses, headers, messages (RFC 5321/5322)
├── lmtp/               Async LMTP server (RFC 2033): codec, session state machine
├── dkim/               DKIM signing and verification (RFC 6376, RFC 8463)
├── arc/                ARC chain validation and sealing (RFC 8617)
└── service/            Binary: wires the above into inbound/outbound pipelines
```

### Dependency graph

```
service
  ├── arc
  │    ├── dkim
  │    │    └── email-primitives
  │    └── email-primitives
  ├── dkim
  ├── lmtp
  │    └── email-primitives
  └── email-primitives
```

## Configuration

Configuration is provided as a TOML file, passed via `--config` or the
`LMTP_DKIM_CONFIG` environment variable.

### Inbound example

```toml
mode = "inbound"

[listen]
socket = "/run/lmtp-dkim/inbound.sock"

[downstream]
socket = "/run/dovecot/lmtp"

[arc]
domain      = "example.com"
selector    = "arc2024"
key_file    = "/etc/lmtp-dkim/arc-ed25519.pem"
authserv_id = "mx.example.com"
```

### Outbound example

```toml
mode = "outbound"

[listen]
socket = "/run/lmtp-dkim/outbound.sock"

[downstream]
host = "relay.example.com"
port = 25

[[dkim]]
domain   = "example.com"
selector = "dkim2024"
key_file = "/etc/lmtp-dkim/dkim-ed25519.pem"
```

### Key format

Private keys must be PKCS#8 PEM files. Ed25519 is recommended for new
deployments; RSA-2048 is also supported for compatibility.

Generate an Ed25519 DKIM key:

```sh
openssl genpkey -algorithm ED25519 -out dkim-ed25519.pem
```

Publish the corresponding public key as a DNS TXT record at
`<selector>._domainkey.<domain>`:

```
v=DKIM1; k=ed25519; p=<base64-encoded-public-key>
```

## Building

```sh
cargo build --workspace
```

## Running tests

```sh
cargo test --workspace
```

See [AGENTS.md](AGENTS.md) for details on the intended testing strategy.

## Linting and formatting

This project uses [pre-commit] for automated checks. After installing
pre-commit:

```sh
pre-commit install
```

All hooks (Rust formatting, Clippy, YAML formatting, actionlint, etc.) will
run automatically on `git commit` and `git push`. CI enforces the same checks.

## Relevant RFCs

| RFC        | Title                                                                                |
| ---------- | ------------------------------------------------------------------------------------ |
| [RFC 2033] | Local Mail Transfer Protocol                                                         |
| [RFC 5321] | Simple Mail Transfer Protocol                                                        |
| [RFC 5322] | Internet Message Format                                                              |
| [RFC 6376] | DomainKeys Identified Mail (DKIM) Signatures                                         |
| [RFC 7601] | Message Header Field for Indicating Message Authentication Status                    |
| [RFC 8301] | Cryptographic Algorithm and Key Usage Update to DomainKeys Identified Mail           |
| [RFC 8463] | A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM) — Ed25519 |
| [RFC 8617] | The Authenticated Received Chain (ARC) Protocol                                      |

[pre-commit]: https://pre-commit.com
[rfc 2033]: https://www.rfc-editor.org/rfc/rfc2033
[rfc 5321]: https://www.rfc-editor.org/rfc/rfc5321
[rfc 5322]: https://www.rfc-editor.org/rfc/rfc5322
[rfc 6376]: https://www.rfc-editor.org/rfc/rfc6376
[rfc 7601]: https://www.rfc-editor.org/rfc/rfc7601
[rfc 8301]: https://www.rfc-editor.org/rfc/rfc8301
[rfc 8463]: https://www.rfc-editor.org/rfc/rfc8463
[rfc 8617]: https://www.rfc-editor.org/rfc/rfc8617
