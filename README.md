<div align="center">
  <h1>@cyanheads/whois-mcp-server</h1>
  <p><b>Look up domain registration, check availability, fetch DNS records, and resolve IPs and ASNs via RDAP and DNS-over-HTTPS via MCP. STDIO or Streamable HTTP.</b>
  <div>6 Tools</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.1.4-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/whois-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.0.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/whois-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/whois-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.0-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/whois-mcp-server/releases/latest/download/whois-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=whois-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvd2hvaXMtbWNwLXNlcnZlciJdfQ==) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22whois-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fwhois-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

---

## Tools

Six tools covering domain intelligence, DNS, and IP/ASN resolution:

| Tool | Description |
|:-----|:------------|
| `whois_lookup_domain` | Full domain registration record — registrar, created/expiry dates, nameservers, EPP status, DNSSEC, registrant org |
| `whois_check_availability` | Check whether a domain is registered or available for registration |
| `whois_get_dns` | DNS records for any hostname via DNS-over-HTTPS (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR) |
| `whois_lookup_ip` | IP or CIDR netblock, org, country, abuse contact, and reverse DNS via RIR RDAP |
| `whois_lookup_asn` | Resolve an ASN to its org name, country, and RIR source |
| `whois_get_dossier` | One-call domain triage — registration + DNS in parallel, normalized into a single record with factual signals |

### `whois_lookup_domain`

Look up a domain's full RDAP registration record.

- RDAP-first via IANA auto-bootstrap — automatically selects the correct registry RDAP server per TLD
- Returns registrar, creation/expiry dates, nameservers, EPP status codes, DNSSEC delegation flag
- Surfaces `registrant_redacted: true` explicitly when privacy redaction is in effect (standard post-GDPR for gTLDs)
- Returns `rdap_coverage: false` for TLDs without RDAP coverage rather than silently failing
- Includes `last_update_of_rdap_db` event timestamp for data freshness transparency

---

### `whois_check_availability`

Check whether a domain name is registered or available to register.

- RDAP 404 = available (`available: true`) — exploits the RDAP spec's intended behavior
- Returns `available: false` with `registrar` and `expiry_date` when registered
- Returns `available: null` with `rdap_coverage: false` for TLDs without RDAP — cannot determine availability
- Optimized for bulk name sweeps — thin response, no unnecessary fields

---

### `whois_get_dns`

Fetch DNS records via DNS-over-HTTPS.

- Cloudflare primary, NextDNS fallback (CAA records always use NextDNS — Cloudflare returns raw hex wire format for them)
- Supports A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR — multiple types in one call
- Returns records with TTLs and the resolving source (`cloudflare` or `nextdns`)
- `nxdomain: true` in result (not an error) when the domain doesn't exist in DNS

---

### `whois_lookup_ip`

Look up an IP address or CIDR block via RIR RDAP.

- Auto-routes to the correct RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC) via IANA IP bootstrap
- Returns netblock CIDR, org name, country, abuse contact email
- Fetches PTR (reverse DNS) via DoH as a best-effort step — `ptr: null` on failure, not an error
- Validates and rejects private/reserved ranges (RFC 1918, loopback, link-local) with a clear error

---

### `whois_lookup_asn`

Resolve an ASN to its org name, country, and RIR.

- Accepts `AS15169` or bare integer `15169` format
- Routes to the correct RIR RDAP endpoint via IANA ASN bootstrap
- Returns `name`, `org`, `country`, `rir`, `start_autnum`, `end_autnum`

---

### `whois_get_dossier`

One-call domain triage aggregating registration and DNS data in parallel.

- Runs RDAP domain lookup and DoH (A, MX, NS, TXT) in parallel via `Promise.allSettled`
- Inferred signals: `age_days`, `privacy_redacted`, `registrar`, `ns_provider` (from NS records), `mx_provider` (from MX records)
- No synthesized risk scores — factual signals only; the agent decides the verdict
- Partial results surfaced when one leg fails (`source_error` on the failed leg)
- Both-legs-fail throws `ServiceUnavailable`; individual leg failures are data, not errors

---

## Features

Built on [`@cyanheads/mcp-ts-core`](https://www.npmjs.com/package/@cyanheads/mcp-ts-core):

- Declarative tool definitions — single file per tool, framework handles registration and validation
- Unified error handling — handlers throw, framework catches, classifies, and formats
- Pluggable auth: `none`, `jwt`, `oauth`
- Swappable storage backends: `in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`
- Structured logging with optional OpenTelemetry tracing
- STDIO and Streamable HTTP transports

Domain and network intelligence:

- RDAP over HTTPS — no port-43 TCP dependency, runs on Node, Bun, and Cloudflare Workers
- IANA bootstrap auto-selection — correct registry RDAP server picked per TLD, RIR, or ASN range; bootstrap JSON cached (TTL 24h) in tenant state
- DNS-over-HTTPS via Cloudflare and NextDNS — resilient dual-provider with per-type routing (NextDNS for CAA; Cloudflare for all others)
- No API keys required — all sources (IANA, registry RDAP endpoints, RIR RDAP, Cloudflare DoH, NextDNS DoH) are public and keyless

Agent-friendly output:

- Explicit coverage signals — `rdap_coverage: false` tells the agent the TLD lacks RDAP rather than returning a confusing error
- Privacy redaction surfaced as a field — `registrant_redacted: true` rather than silently absent contact data
- Partial failure model — `whois_get_dossier` marks individual legs with `source_error` and continues; only both-legs-fail escalates to an error
- Factual signals, not scores — `age_days`, `privacy_redacted`, `ns_provider`, `mx_provider` are real data; agents chain into threat-intel or risk servers for enrichment

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
# Server listens at http://localhost:3010/mcp
```

### Prerequisites

- [Bun v1.3.0](https://bun.sh/) or higher (or Node.js v24+).
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
| `src/index.ts` | `createApp()` entry point — registers tools and inits services. |
| `src/config/` | Server-specific environment variable parsing and validation (Zod). |
| `src/services/rdap/` | RDAP client — IANA bootstrap cache, domain/IP/ASN lookup, retry. |
| `src/services/doh/` | DNS-over-HTTPS client — Cloudflare primary, NextDNS fallback. |
| `src/mcp-server/tools/` | Tool definitions (`*.tool.ts`). |
| `tests/` | Vitest tests mirroring `src/`. |
| `docs/` | Design and API reference documents. |

---

## Development guide

See [`CLAUDE.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging, `ctx.state` for tenant-scoped storage (IANA bootstrap cache)
- Register new tools via `src/index.ts` tools array
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

---

## Contributing

Issues and pull requests are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
