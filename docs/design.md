# whois-mcp-server — Design

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations |
|:-----|:------------|:-----------|:------------|
| `whois_lookup_domain` | Look up a domain's registration record — registrar, created/expiry dates, nameservers, EPP status codes, DNSSEC flag, and registrant org (where not privacy-redacted). RDAP-first via IANA auto-bootstrap. One normalized shape regardless of TLD. When the TLD has no RDAP coverage, returns `rdap_coverage: false`. | `domain: string` (valid FQDN) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_check_availability` | Check whether a domain name is registered or available for registration. RDAP 404 = available (modeled as data: `available: true`, not an error). Returns `available: false` with `registrar` and `expiry_date` when registered. When the TLD has no RDAP coverage, returns `available: null` with `rdap_coverage: false` — cannot determine availability. Designed for "can I register X" and bulk name sweeps. | `domain: string` (valid FQDN) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_get_dns` | Fetch DNS records for a domain via DNS-over-HTTPS (Cloudflare 1.1.1.1 primary, Google 8.8.8.8 fallback). Supports A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR. Returns records with TTLs and the resolving source. NXDOMAIN is returned as `nxdomain: true` in the result, not as an error. | `domain: string` (valid FQDN), `types: z.enum(["A","AAAA","MX","TXT","NS","CNAME","SOA","CAA","PTR"])[]` (default: `["A","AAAA","MX","TXT","NS"]`) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_lookup_ip` | Look up an IP address or CIDR block via RIR RDAP (ARIN/RIPE/APNIC/LACNIC/AFRINIC, auto-routed via IANA bootstrap). Returns netblock, org, country, CIDR, abuse contact email, and reverse DNS (PTR) via DoH. Private/reserved ranges (RFC 1918, loopback, link-local) return a validation error — no RDAP record exists for them. | `ip: string` (valid IPv4, IPv6, or CIDR notation) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_lookup_asn` | Resolve an ASN (e.g., `AS15169` or `15169`) to its org name, country, and RIR source via RIR RDAP. Distinct from IP lookup — entry point is the ASN itself, not an IP within the block. | `asn: string` (format: `AS<number>` or bare integer, e.g., `AS15169` or `15169`) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_get_dossier` | One-call domain triage: registration + DNS (A, MX, NS, TXT) in parallel, normalized into a single record with factual signals — domain age in days, privacy-redacted flag, registrar name, NS provider inferred from NS records, mail provider inferred from MX. No synthesized scores. Partial results surfaced when one leg fails (registration or DNS marked with `source_error`); both-legs-fail throws `ServiceUnavailable`. | `domain: string` (valid FQDN) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |

### Resources

None. All data is ephemeral and query-driven — no stable URI addressing fits the domain. A tool-only agent has full access to all server capabilities.

### Prompts

None. This is a data/lookup server with no recurring interaction patterns that warrant a reusable template.

---

## Overview

whois-mcp-server is a multi-source domain and IP intelligence server that normalizes RDAP and DNS-over-HTTPS into a single consistent shape. The agent gets one clean answer regardless of TLD, RIR, or data sparsity — no per-registry format wrangling, no IANA bootstrap logic. Port-43 WHOIS is deferred (see Design Decisions).

**Audience:** developers, SRE/ops, and security/threat-triage. The "who owns this domain, when does it expire, what does it resolve to, who runs this IP" workflow is daily work across all three.

**Runtime split:** RDAP and DoH are HTTPS/JSON and work on Node, Bun, and Cloudflare Workers. Port-43 WHOIS is raw TCP (`net.Socket`) — Node/Bun only. See Design Decisions for why WHOIS-43 is deferred.

---

## Requirements

- Domain registration lookup via RDAP with IANA bootstrap (auto-selects per-TLD RDAP server)
- Domain availability check (RDAP 404 = domain not registered = available)
- DNS record fetching via DNS-over-HTTPS for A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR record types
- IP/CIDR → netblock, org, abuse contact via RIR RDAP (IANA bootstrap for IP space)
- ASN resolution via RIR RDAP
- One-call domain dossier aggregating registration + DNS in parallel
- Privacy redaction surfaced explicitly, not silently omitted
- No synthesized risk scores — factual signals only
- All sources keyless; rate limits respected with retry + backoff
- No auth required

---

## Services

| Service | Wraps | Used By |
|:--------|:------|:--------|
| `rdap-service` | RDAP (IANA bootstrap JSON + per-TLD/RIR RDAP endpoints) | `whois_lookup_domain`, `whois_check_availability`, `whois_lookup_ip`, `whois_lookup_asn` |
| `doh-service` | Cloudflare DoH (`https://cloudflare-dns.com/dns-query`) + Google DoH fallback (`https://dns.google/resolve`) | `whois_get_dns`, `whois_lookup_ip` (PTR), `whois_get_dossier` |

Port-43 WHOIS deferred — see Design Decisions.

---

## Config

| Env Var | Required | Default | Description |
|:--------|:---------|:--------|:------------|
| `RDAP_TIMEOUT_MS` | No | `5000` | HTTP timeout for RDAP requests |
| `DOH_TIMEOUT_MS` | No | `3000` | HTTP timeout for DoH requests |
| `RDAP_MAX_RETRIES` | No | `2` | Max retry attempts on transient RDAP failures |
| `DOH_MAX_RETRIES` | No | `2` | Max retry attempts on transient DoH failures |

All standard framework env vars apply (`MCP_LOG_LEVEL`, transport, auth, OTel). No external API keys required.

---

## Implementation Order

1. Config — `src/config/server-config.ts` (timeouts, retries)
2. RDAP service — IANA bootstrap cache + domain/IP/ASN lookup with retry
3. DoH service — A/AAAA/MX/TXT/NS/CNAME/SOA/CAA/PTR resolution with Google fallback
4. `whois_lookup_domain` — RDAP domain; parse vcard + events + entities into normalized schema
5. `whois_check_availability` — thin wrapper on RDAP 404 behavior
6. `whois_get_dns` — DoH multi-type fetch; parallel per-type requests
7. `whois_lookup_ip` — RDAP IP/CIDR; extract netblock + entities + abuse contact
8. `whois_lookup_asn` — RDAP autnum
9. `whois_get_dossier` — `Promise.allSettled` fan-out across RDAP + DoH; assemble normalized dossier

Each step is independently testable.

---

## Error Contracts

Typed error contracts for each tool's known domain failure modes. Baseline codes (`InternalError`, `ServiceUnavailable`, `Timeout`, `ValidationError`) bubble freely and don't need declaring.

### `whois_lookup_domain`

| reason | code | when |
|:-------|:-----|:-----|
| `rdap_no_coverage` | `NotFound` | TLD has no RDAP server in IANA bootstrap — cannot perform lookup |
| `domain_not_found` | `NotFound` | RDAP server returned 404 — domain not registered (may want `whois_check_availability` instead) |
| `invalid_domain` | `InvalidParams` | Input is not a valid FQDN |

### `whois_check_availability`

| reason | code | when |
|:-------|:-----|:-----|
| `rdap_no_coverage` | `NotFound` | TLD has no RDAP server — `available` is `null`, cannot determine registration status |
| `invalid_domain` | `InvalidParams` | Input is not a valid FQDN |

Note: RDAP 404 is **not** an error for this tool — it is the primary availability signal (`available: true`).

### `whois_get_dns`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_domain` | `InvalidParams` | Input is not a valid FQDN |

Note: NXDOMAIN (`Status: 3`) is **not** an error — returned as `nxdomain: true` in the result.

### `whois_lookup_ip`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_ip` | `InvalidParams` | Input is not a valid IPv4, IPv6, or CIDR address |
| `private_range` | `InvalidParams` | Input is a private/reserved range (RFC 1918, loopback, link-local) — no RIR RDAP record exists |
| `ip_not_found` | `NotFound` | RIR RDAP returned 404 — no netblock record for this address |

### `whois_lookup_asn`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_asn` | `InvalidParams` | Input does not match `AS<number>` or bare integer format |
| `asn_not_found` | `NotFound` | RDAP returned 404 — ASN not found in any RIR |

### `whois_get_dossier`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_domain` | `InvalidParams` | Input is not a valid FQDN |
| `both_legs_failed` | `ServiceUnavailable` | Both RDAP and DoH legs failed — no data returned |

Note: single-leg failures are partial results (`source_error` on the failed leg), not thrown errors.

---

## Domain Mapping

### Nouns × Operations → API Endpoints

| Noun | Operations | RDAP Path | DoH Path |
|:-----|:-----------|:----------|:---------|
| Domain | lookup, availability | `GET https://<tld-rdap>/domain/<name>` | — |
| DNS Records | query by type | — | `GET https://cloudflare-dns.com/dns-query?name=<n>&type=<t>` |
| IP Network | lookup | `GET https://<rir-rdap>/ip/<addr>` | PTR: `GET …?name=<reversed>.in-addr.arpa&type=PTR` |
| ASN | lookup | `GET https://<rir-rdap>/autnum/<num>` | — |
| IANA Bootstrap | read-only cache | `GET https://data.iana.org/rdap/dns.json` (domain) | — |
|  |  | `GET https://data.iana.org/rdap/ipv4.json` + `ipv6.json` (IP) | — |
|  |  | `GET https://data.iana.org/rdap/asn.json` (ASN) | — |

---

## Workflow Analysis

### `whois_get_dossier` — 2 parallel upstream legs

| # | Call | Purpose |
|:--|:-----|:--------|
| 1a | RDAP domain lookup (bootstrap → registry server) | Registration record: registrar, dates, nameservers, status, DNSSEC |
| 1b | DoH A + MX + NS + TXT in parallel | DNS resolution state |
| 2 | Assemble normalized dossier from `Promise.allSettled` | Merge, compute factual signals (age, privacy flag, inferred providers) |

Both legs run in parallel. A failed RDAP leg → dossier marks registration as `unavailable` with `source_error`. A failed DoH leg → dossier marks DNS as `unavailable`. At least one leg must succeed; if both fail, throw `ServiceUnavailable`.

### `whois_lookup_ip` — 2 sequential steps

| # | Call | Purpose |
|:--|:-----|:--------|
| 1 | RDAP IP lookup (IANA IP bootstrap → RIR RDAP server) | Netblock, org, CIDR, abuse contact |
| 2 | DoH PTR (`<reversed>.in-addr.arpa`) | Reverse DNS hostname |

PTR is best-effort — failure produces `ptr: null`, not an error.

---

## Design Decisions

### WHOIS-43 (port 43) — deferred

**Decision:** WHOIS-43 is deferred from v0.1. The server ships RDAP + DoH only.

**Reasoning:**
- RDAP covers the vast majority of domains agents encounter. `.com`, `.net`, `.org`, and most ccTLDs have RDAP. The TLDs with thin RDAP are mostly obscure ccTLDs where WHOIS-43 response quality is also poor (inconsistent encoding, non-standard field names).
- Port-43 WHOIS is raw TCP (`net.Socket` in Node) — it blocks Workers deployment. Since RDAP + DoH are both HTTPS/JSON, the server is Workers-hostable without WHOIS-43.
- Free-text WHOIS parsing (the only way to normalize port-43 output) is fragile, registry-specific, and maintenance-heavy. RDAP already provides structured data; building and maintaining a parser for dozens of TLD-specific text formats adds complexity for marginal coverage gain.
- The "thin-coverage TLD" scenario the idea.md flagged is less common in practice: the primary RDAP fallback for truly uncovered TLDs is to surface `rdap_coverage: false` with the raw IANA bootstrap lookup result, which is more honest than a best-effort text parse.

**If added later:** WHOIS-43 lives in its own `whois43-service.ts`, added as a third fallback arm in `whois_lookup_domain` only (the tool where it adds coverage). DoH and IP/ASN tools are unaffected.

### `rdap.org` vs direct IANA bootstrap

**Decision:** Use `rdap.org` as the primary RDAP proxy during development, but the service layer resolves bootstrap directly from IANA (`data.iana.org/rdap/dns.json`) and caches it for production.

**Reasoning:** `rdap.org` is a convenience proxy that handles bootstrap internally but introduces an intermediary. Direct IANA bootstrap + per-registry RDAP is the canonical path and gives control over timeouts and retries per hop. Cache the IANA bootstrap JSON (TTL: 24h) to avoid a bootstrap lookup on every domain query.

### CAA record format — Cloudflare returns raw hex, Google returns human-readable

**Decision:** Use Cloudflare as primary DoH; fall back to Google for CAA records specifically, or decode the hex wire format in the service layer.

**Observed:** Cloudflare DoH returns CAA records as raw hex wire format (`\# 19 00 05 69 73 73 75 65...`). Google DoH returns human-readable text (`0 issue "letsencrypt.org"`). The service layer must decode the Cloudflare hex format or prefer Google DoH for CAA queries. Implementation will use Google for CAA and Cloudflare for all others.

### No resources or prompts

**Decision:** No MCP resources or prompts defined.

**Reasoning:** All data is query-driven with no stable URI addressing — you can't address a domain's RDAP record by a URI that means anything across sessions. Prompts would add no value: the tools are self-sufficient and the use cases (lookup, check, fetch) don't benefit from a reusable message template.

### `whois_get_dossier` includes factual signals, not scores

**Decision:** Dossier surfaces `age_days`, `privacy_redacted`, `registrar`, `ns_provider`, `mx_provider` as discrete fields. No composite score.

**Reasoning:** A fabricated threat score built from arbitrary weights is epistemically empty and misleads both agents and humans. The dossier gives the inputs; the agent or human analyst decides the verdict. Surfacing the components lets the agent chain into nist-nvd, attack-surface, or threat-intel servers for enrichment.

---

## Known Limitations

- **Privacy redaction is the norm (GDPR/ICANN 2018+).** Registrant contact info is redacted for most gTLD registrations. The server surfaces `registrant_redacted: true` explicitly rather than implying missing data. Some ccTLD registrars still expose full registrant data.
- **RDAP coverage gaps.** Some ccTLDs lack RDAP entirely. The server returns `rdap_coverage: false` in these cases; WHOIS-43 fallback is deferred (see Design Decisions).
- **Rate limits vary by registry.** Verisign (`.com`/`.net`) is liberal; some ccTLD registries are strict. The service layer applies per-domain backoff, but sustained bulk lookups may hit registry limits. No rate-limit advisory is surfaced upward — the `ServiceUnavailable` error is the signal.
- **RDAP data freshness.** RDAP servers have their own update lag vs. the authoritative registry database. The `last update of RDAP database` event from the response is included in output for transparency.
- **IPv6 PTR reverse DNS** uses `.ip6.arpa` format. Handled by the service layer.

---

## API Reference

### RDAP response shape (domain)

Top-level fields confirmed from live probe (`github.com`):
- `objectClassName: "domain"` | `ldhName` | `handle` | `status[]` (EPP codes) | `nameservers[]` | `secureDNS.delegationSigned`
- `events[]`: `{ eventAction, eventDate }` — actions include `registration`, `expiration`, `last changed`, `last update of RDAP database`
- `entities[]`: each has `roles[]`, `vcardArray` (RFC 6350 format), nested `entities[]` (e.g., registrar → abuse contact), `publicIds[]`
- `links[]`: `self` (authoritative URL), `related` (registrar RDAP URL)

Registrant contact: nested inside the registrar entity's `entities[]` or top-level with role `registrant`. Post-GDPR: typically absent or contains only `roles` and no vcard contact data.

### RDAP response shape (ip network)

Confirmed from live probe (`8.8.8.8`):
- `objectClassName: "ip network"` | `handle` | `startAddress` | `endAddress` | `ipVersion` | `name` | `type` | `parentHandle`
- `cidr0_cidrs[]`: `{ v4prefix, length }` or `{ v6prefix, length }`
- `entities[]`: role `registrant` (org), nested `entities[]` with role `abuse` (includes email in vcard), role `administrative`/`technical`
- `country` field is often `null` even for geo-routed blocks — don't rely on it

### RDAP response shape (autnum)

Confirmed from live probe (`AS15169`):
- `objectClassName: "autnum"` | `handle` (e.g., `AS15169`) | `startAutnum` | `endAutnum` | `name` | `type`
- `entities[]`: role `registrant` with org name in vcard `fn`

### RDAP 404 semantics

A `404` response from the TLD's RDAP server means the domain is **not registered** (available). This is the RDAP spec behavior — no record = not registered. The `whois_check_availability` tool exploits this as the primary availability signal.

### DoH response shape (Cloudflare)

`GET https://cloudflare-dns.com/dns-query?name=<domain>&type=<TYPE>` with `Accept: application/dns-json`

- `Status: 0` = `NOERROR`, `Status: 3` = `NXDOMAIN` (domain doesn't exist in DNS)
- `Answer[]`: `{ name, type (numeric), TTL, data (string) }`
- `Authority[]`: present on NXDOMAIN/NOERROR-with-no-records (SOA of the zone)
- DNS type numbers: A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, AAAA=28, CAA=257

**CAA quirk:** Cloudflare returns CAA `data` as raw hex wire format (`\# 19 00 05 ...`). Google DoH returns human-readable (`0 issue "letsencrypt.org"`). Use Google DoH for CAA queries.

**PTR (reverse DNS):** construct query name as `<reversed-octets>.in-addr.arpa` (IPv4) or `<nibble-reversed>.ip6.arpa` (IPv6).

### DoH rate limits

Cloudflare and Google DoH are public resolvers with no documented rate limits for reasonable use. The framework's `withRetry` handles transient failures.

### RDAP rate limits

Per-registry: Verisign (`.com`/`.net`) — no documented limit, liberal in practice. RIRs (ARIN, RIPE, APNIC, etc.) — no published limit but enforce per-IP throttling. Retry on 429 with exponential backoff (base 2s for rate-limited responses).
