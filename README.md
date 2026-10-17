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

- Takes a fully qualified domain name and picks the registry's RDAP server through IANA bootstrap.
- Returns registrar, dates, nameservers, EPP status, DNSSEC, and `registrant_redacted`; DNSSEC and privacy stay `null` when the registry gives no evidence. Fails with `rdap_no_coverage`, `domain_not_found`, or `rdap_invalid_domain_response` (the response doesn't match the queried domain).
- `include_registrar: true` follows one registrar RDAP referral and adds `registrar_detail` (`found`, `no_referral`, or `failed`, plus source URL). Off by default; limited by `RDAP_TIMEOUT_MS`, and a failure keeps the registry result.

---

### `whois_check_availability` <sub>tool</sub>

- Takes a fully qualified domain name.
- Returns `registration_status: registered | not_found | unknown`. `available` is `false` for a found registration and `null` otherwise, never `true`: a 404 means no record, not that the name can be registered.
- Known ICANN subdomains return `non_registrable_domain` with their registrable parent.

---

### `whois_get_dns` <sub>tool</sub>

- Takes an ASCII DNS name (underscore labels like `_dmarc.example.com` are fine), up to 253 characters with 1–63-character labels. Optional `types`: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR; defaults to A, AAAA, MX, TXT, NS.
- Returns records with TTLs and `query_sources: [{type, source}]`, including empty answers and NXDOMAIN. Legacy `source` is `cloudflare` if any query got a successful Cloudflare response, otherwise `nextdns`.
- Resolver failure codes and truncated responses return errors after retries and fallback. CAA queries go to NextDNS.

---

### `whois_lookup_ip` <sub>tool</sub>

- Takes an IPv4/IPv6 address with an optional CIDR prefix (0–32 / 0–128). Echoes the original `ip`.
- Returns org, country, abuse contact, provider CIDRs in `cidrs` (`cidr` only when there is exactly one), and a best-effort reverse DNS lookup: `ptr_status: found | not_found | failed`, with `ptr_source_error` on failure while the RDAP data is kept.
- `include_routing: true` adds `routing` (`found | not_found | failed`) with the RIS-observed prefix and `origin_asns`, from [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info). Off by default; a routing failure keeps the RDAP and PTR results.
- Fails with `invalid_ip`, `ip_not_found`, `ip_no_rdap_route` (no RIR covers the address; not retryable), or `private_range` for `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `255.0.0.0/8`, `::1/128`, `fc00::/7`, and `fe80::/10`.

---

### `whois_lookup_asn` <sub>tool</sub>

- Takes an ASN from 1 to 4294967295, with an optional `AS` prefix (e.g., `AS15169`, `AS 15169`, `+15169`). Out-of-range numbers fail with `invalid_asn`.
- Returns `name`, `org_name`, `country`, `rir`, `start_autnum`, and `end_autnum`; fails with `asn_not_found` when no record exists.

---

### `whois_get_dossier` <sub>tool</sub>

- Takes a fully qualified domain name and runs the registration and A/MX/NS/TXT lookups in parallel.
- Returns registration, DNS, domain age, privacy status, and inferred NS/MX providers. A failed lookup leaves the other's data in place and sets `rdap_source_error` or `dns_source_error`; `both_legs_failed` means neither succeeded.
- A null MX (`0 .`) means the domain accepts no mail.

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
- Privacy redaction is `true` when the registry shows it and `null` when there's no evidence
- Partial failure model — `whois_get_dossier` marks a failed lookup with a `source_error` field and continues; only both failing is an error
- Factual signals, not scores — `age_days`, `privacy_redacted`, `ns_provider`, `mx_provider` are real data, not synthesized risk scores

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
