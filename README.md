<div align="center">
  <h1>@cyanheads/whois-mcp-server</h1>
  <p><b>Look up domain registration, check registry record status, fetch DNS records, and resolve IPs and ASNs over RDAP and DNS-over-HTTPS via MCP. STDIO or Streamable HTTP.</b>
  <div>6 Tools</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.2.1-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/whois-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.3.1-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/whois-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/whois-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.3-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/whois-mcp-server/releases/latest/download/whois-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=whois-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvd2hvaXMtbWNwLXNlcnZlciJdfQ==) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22whois-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fwhois-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

---

## Overview

Domain and network intelligence via RDAP and DNS-over-HTTPS. Look up domain registrations, check registry record status, fetch DNS records, and resolve IPs and ASNs to their registries. No API key required.

### Tools

| Tool | Description |
|:-----|:------------|
| `whois_lookup_domain` | Full domain registration record — registrar, created/expiry dates, nameservers, EPP status, DNSSEC, registrant org |
| `whois_check_availability` | Check registry record presence; missing records do not establish registration eligibility |
| `whois_get_dns` | DNS owner records via DNS-over-HTTPS (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR) |
| `whois_lookup_ip` | IP or CIDR netblock, org, country, abuse contact, and reverse DNS via RIR RDAP |
| `whois_lookup_asn` | Resolve an ASN to its org name, country, and RIR source |
| `whois_get_dossier` | One-call domain triage — registration + DNS in parallel, normalized into a single record with factual signals |

---

## Capability reference

### `whois_lookup_domain` <sub>tool</sub>

- Accepts a fully qualified domain name and selects the registry RDAP server through IANA bootstrap.
- Returns registrar, registration dates, nameservers, EPP status, DNSSEC, and `registrant_redacted`; throws `rdap_no_coverage` or `domain_not_found` when no record can be returned.
- Absent DNSSEC and privacy evidence stay `null`. Public jCard `org` is independent of redacted contact fields; a person's formatted name is not an organization.
- Primary responses must identify the queried domain (case and equivalent IDNA spellings are accepted). Malformed/error payloads and mismatched objects fail with `rdap_invalid_domain_response`; sparse matching name-only records remain valid. Dossiers retain successful DNS and disclose this RDAP failure.
- `include_registrar: true` follows one registrar RDAP referral and returns separate `registrar_detail` with `found`, `no_referral`, or `failed` status and source URL. Registry dates, nameservers, status, and DNSSEC remain authoritative. Default lookups make no registrar request. The optional exchange has no retries, at most five guarded redirects, and one `RDAP_TIMEOUT_MS` deadline; failure retains the registry result, cancellation propagates. Destination checks are best-effort against DNS rebinding.

---

### `whois_check_availability` <sub>tool</sub>

- Accepts a fully qualified domain name for a registration check.
- Returns `registration_status: registered | not_found | unknown`. `available` is `false` for a found registration and `null` otherwise; it never returns `true`. RDAP 404 establishes record absence, not eligibility to register.
- Known ICANN subdomains return `non_registrable_domain` with their registrable parent; the query is never silently rewritten. Private suffixes do not create independent registration boundaries, and unlisted suffixes retain IANA coverage handling.

---

### `whois_get_dns` <sub>tool</sub>

- Accepts an ASCII DNS owner name, including underscore labels (`_dmarc.example.com`) and one terminal root dot. Names normalize to at most 253 characters, with nonempty 1–63-character labels; spaces, URLs, consecutive dots, and multiple terminal dots are rejected. Optional nonempty `types`: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR; omission defaults to A, AAAA, MX, TXT, NS. Duplicate types are queried once.
- Returns records with TTLs and ordered `query_sources: [{type, source}]`, including empty answers and NXDOMAIN. Legacy `source` is `cloudflare` if any query consumed a successful Cloudflare response, otherwise `nextdns`. NXDOMAIN is data about the terminal resolution target; preceding CNAME answers remain available to diagnose dangling aliases.
- NOERROR/NODATA stays empty data; resolver failure codes and truncated responses return errors after retries/fallback. CAA queries use NextDNS once per retry sequence. TXT values, including duplicates, empty strings and newlines, remain complete on both surfaces and use content-sized Markdown fences for literal presentation.

---

### `whois_lookup_ip` <sub>tool</sub>

- Accepts a complete IPv4/IPv6 address with at most one decimal CIDR prefix (0–32 / 0–128); no whitespace, zone IDs, or brackets. Queries the base address and echoes the original `ip`. IPv4-mapped IPv6 uses the embedded IPv4 for policy, RDAP, and PTR; other IPv6 uses 32 reversed PTR nibbles.
- Returns every provider CIDR in ordered `cidrs`; `cidr` appears only for exactly one component. Start/end addresses remain authoritative; missing CIDR extensions produce an empty list rather than an inferred prefix.
- Best-effort PTR uses `ptr_status: found | not_found | failed`; failures include `ptr_source_error` and retain RDAP data. Only reachable owner-matched PTR records are selected, through at most five alias transitions under one `DOH_TIMEOUT_MS` deadline. Cancellation propagates.
- `include_routing: true` adds `routing` with `found | not_found | failed`, a RIS-observed prefix and all `origin_asns` accepted by `whois_lookup_asn`. [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info) uses RISwhois dumps updated every eight hours; routing observations are separate from registry ownership. One optional request runs alongside PTR after successful RDAP, under a fixed 3000 ms deadline including the response body, without retries or ASN-detail fan-out. Omission/false adds no dependency; routing failure retains RDAP/PTR and cancellation propagates.
- Semantic input failures return `invalid_ip`; RIR 404 returns `ip_not_found`. A successfully loaded bootstrap with no covering route returns non-retryable `ip_no_rdap_route`, distinct from bootstrap failure.
- `private_range` enforces an explicit policy: IPv4 `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `255.0.0.0/8`; IPv6 `::1/128`, `fc00::/7`, `fe80::/10`. Other special-use addresses remain eligible for registry records or normal no-coverage/not-found outcomes.

---

### `whois_lookup_asn` <sub>tool</sub>

- Accepts a decimal ASN from 1 to 4294967295 with an optional case-insensitive `AS` prefix and leading `+` (e.g., `AS15169`, `AS 15169`, `+15169`). Outer whitespace, whitespace after `AS`, and arbitrary zero-padding are allowed; whitespace inside digits or after `+`, suffixes, and decimals fail syntax validation. Out-of-range numbers retain `invalid_asn`.
- Returns `name`, `org_name`, `country`, `rir`, `start_autnum`, and `end_autnum`; throws `asn_not_found` when no ASN record exists.

---

### `whois_get_dossier` <sub>tool</sub>

- Accepts a fully qualified domain name for parallel registration and A/MX/NS/TXT lookups.
- Returns registration, DNS, domain age, privacy status, and inferred NS/MX providers. Individual failures remain partial data in `rdap_source_error` or `dns_source_error`; `both_legs_failed` means neither source succeeded.
- Null MX stays `0 .` and explicitly means the domain accepts no mail; it never implies a mail provider. Ordinary MX hostnames retain their normalized form.
- Missing RDAP evidence, no coverage, and RDAP failure keep DNSSEC/privacy unknown. A registry miss is record absence without an eligibility guarantee; DNS failure codes and truncation populate `dns_source_error`.

Identifier syntax is advertised in JSON Schema and rejected with `InvalidParams` / `invalid_arguments` before network calls. Complete IP parsing, prefix ranges, numeric ASN bounds, and exclusion policy retain typed semantic errors. Registration names use hostname grammar separately from DNS underscore/root-dot names; ASN and CIDR inputs have no arbitrary length ceiling.

---

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

RDAP / DNS-specific:

- RDAP over HTTPS — no port-43 TCP dependency
- IANA bootstrap auto-selection — correct registry RDAP server picked per TLD, RIR, or ASN range; bootstrap JSON cached in-memory for 24h
- DNS-over-HTTPS via Cloudflare and NextDNS — dual-provider with per-type routing (NextDNS for CAA; Cloudflare for all others) and automatic fallback
- No API keys required — all sources (IANA, registry RDAP endpoints, RIR RDAP, Cloudflare DoH, NextDNS DoH, optional RIPEstat Network Info) are public and keyless

Agent-friendly output:

- Coverage signaled two ways — `rdap_coverage: false` returned as data by `whois_check_availability` and `whois_get_dossier`, while `whois_lookup_domain` throws `rdap_no_coverage` for the same case
- Privacy redaction surfaced from explicit registrant evidence — `true` for redaction and `null` when evidence is absent; organization data is independent
- Partial failure model — `whois_get_dossier` marks individual legs with a `source_error` field and continues; only both-legs-fail escalates to an error
- Factual signals, not scores — `age_days`, `privacy_redacted`, `ns_provider`, `mx_provider` are real data, not synthesized risk scores
- Provider text retains its structured value; Markdown-sensitive punctuation and whitespace render in literal fences across registration, dossier, IP and ASN results, including optional registrar detail.

---

## Getting started

No API keys or accounts required. Add the following to your MCP client configuration file.

```json
{
  "mcpServers": {
    "whois-mcp-server": {
      "type": "stdio",
      "command": "bunx",
      "args": ["@cyanheads/whois-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with npx (no Bun required):

```json
{
  "mcpServers": {
    "whois-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@cyanheads/whois-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "whois-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "MCP_TRANSPORT_TYPE=stdio",
        "ghcr.io/cyanheads/whois-mcp-server:latest"
      ]
    }
  }
}
```

For Streamable HTTP, set the transport and start the server:

```sh
MCP_TRANSPORT_TYPE=http MCP_HTTP_PORT=3010 bun run start:http
# Server listens at http://127.0.0.1:3010/mcp
```

### Prerequisites

- [Bun v1.4.0](https://bun.sh/) or higher (or Node.js v24+).
- No API keys required — all data sources are public.

### Installation

1. **Clone the repository:**

```sh
git clone https://github.com/cyanheads/whois-mcp-server.git
```

2. **Navigate into the directory:**

```sh
cd whois-mcp-server
```

3. **Install dependencies:**

```sh
bun install
```

4. **Configure environment:**

```sh
cp .env.example .env
# All vars are optional — defaults work for most use cases
```

---

## Configuration

| Variable | Description | Default |
|:---------|:------------|:--------|
| `RDAP_TIMEOUT_MS` | HTTP timeout for RDAP requests in milliseconds. | `5000` |
| `DOH_TIMEOUT_MS` | HTTP timeout for DNS-over-HTTPS requests in milliseconds. | `3000` |
| `RDAP_MAX_RETRIES` | Max retry attempts on transient RDAP failures. | `2` |
| `DOH_MAX_RETRIES` | Max retry attempts on transient DoH failures. | `2` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `OTEL_ENABLED` | Enable [OpenTelemetry instrumentation](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

---

## Running the server

### Local development

- **Build and run:**

  ```sh
  bun run rebuild
  bun run start:stdio
  # or
  bun run start:http
  ```

- **Run checks and tests:**

  ```sh
  bun run devcheck   # Lint, format, typecheck, security
  bun run test       # Vitest test suite
  bun run lint:mcp   # Validate MCP definitions against spec
  ```

### Docker

```sh
docker build -t whois-mcp-server .
docker run --rm -p 3010:3010 whois-mcp-server
```

The Dockerfile defaults to HTTP transport, stateless session mode, and logs to `/var/log/whois-mcp-server`. OpenTelemetry peer dependencies are installed by default — build with `--build-arg OTEL_ENABLED=false` to omit them.

---

## Project structure

| Path | Purpose |
|:-----|:--------|
| `src/index.ts` | Entry point — starts the app. |
| `src/app.ts` | `createApp()` options — registers tools, inits services, declares the session mode. |
| `src/config/` | Server-specific environment variable parsing and validation (Zod). |
| `src/services/rdap/` | RDAP client — IANA bootstrap cache, domain/IP/ASN lookup, retry. |
| `src/services/doh/` | DNS-over-HTTPS client — Cloudflare primary, NextDNS fallback. |
| `src/services/routing/` | Optional RIPEstat RIS routing observations with a bounded exchange. |
| `src/mcp-server/tools/` | Tool definitions (`*.tool.ts`). |
| `tests/` | Vitest tests mirroring `src/`. |
| `docs/` | Design and API reference documents. |

---

## Development guide

See [`CLAUDE.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging
- Register new tools via `src/app.ts`'s `tools` array
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

---

## Contributing

Issues are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
