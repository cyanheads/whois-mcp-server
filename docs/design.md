# whois-mcp-server — Design

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations |
|:-----|:------------|:-----------|:------------|
| `whois_lookup_domain` | Registry registration record; nullable DNSSEC/privacy evidence and public registrant org. Optional registrar contact detail remains nested without overriding registry authority. No coverage throws `rdap_no_coverage`; a missing registry object throws `domain_not_found`. | `domain: string` (hostname grammar), `include_registrar: boolean = false` | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_check_availability` | Registry record status: registered/false, not_found/null, or unknown/null for absent coverage. No registration eligibility guarantee. Known ICANN subdomains are rejected with a parent hint; private suffixes are excluded from registration-boundary recognition. | `domain: string` (hostname grammar) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_get_dns` | DNS records with TTLs and ordered query provenance. NOERROR/NODATA and NXDOMAIN are data; failure codes and truncated replies are errors after fallback. Complete literal TXT output. | `domain: string` (ASCII DNS owner, underscores and one root dot), nonempty `types[]` (default A/AAAA/MX/TXT/NS) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_lookup_ip` | Look up an IP/CIDR base address via RIR RDAP. Returns netblock, org, country, CIDRs, abuse contact, and best-effort PTR. Optional RIS prefix/origin observations remain separate from ownership. Explicit excluded ranges return `private_range`; other special-use addresses remain eligible for RDAP. IPv4-mapped IPv6 uses embedded IPv4 for lookup and PTR. | `ip: string` (complete IPv4/IPv6; optional decimal CIDR prefix within 0–32/0–128; no whitespace, zone IDs, or brackets), `include_routing: boolean = false` | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
| `whois_lookup_asn` | Resolve an ASN to org, country, and RIR. Validate the whole trimmed decimal token in 1–4294967295 before lookup. | `asn: string` (optional case-insensitive `AS` prefix, whitespace after `AS`, and leading `+`; no whitespace inside digits or after `+`) | `readOnlyHint: true, idempotentHint: true, openWorldHint: true` |
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
- Registry record status without asserting registration eligibility
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
| `rdap-service` | RDAP (IANA bootstrap JSON + per-TLD/RIR RDAP endpoints) | `whois_lookup_domain`, `whois_check_availability`, `whois_lookup_ip`, `whois_lookup_asn`, `whois_get_dossier` |
| `doh-service` | Cloudflare DoH (`https://cloudflare-dns.com/dns-query`) + NextDNS DoH (`https://dns.nextdns.io`) for CAA and as fallback | `whois_get_dns`, `whois_lookup_ip` (PTR), `whois_get_dossier` |
| `routing-service` | RIPEstat Network Info (`https://stat.ripe.net/data/network-info/data.json`) using RISwhois eight-hour dumps | `whois_lookup_ip` only when `include_routing: true` |

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
3. DoH service — A/AAAA/MX/TXT/NS/CNAME/SOA/CAA/PTR resolution with NextDNS fallback
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
| `domain_not_found` | `NotFound` | RDAP server returned 404 — registry object absent, without an eligibility conclusion |
| `rdap_invalid_domain_response` | `ServiceUnavailable` | Primary source is not a matching successful domain object; not retried |
| `invalid_arguments` | `InvalidParams` | Input does not match serialized registration-name syntax |

### `whois_check_availability`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_arguments` | `InvalidParams` | Input does not match serialized registration-name syntax |
| `non_registrable_domain` | `ValidationError` | ICANN-recognized subdomain, with exact registrable-parent hint |
| `rdap_invalid_domain_response` | `ServiceUnavailable` | Primary source is not a matching successful domain object; not retried |

RDAP 404 is record-status data (`registration_status: not_found`, `available: null`). Missing coverage yields `unknown/null` with `rdap_coverage: false`. Neither establishes registration eligibility.

### `whois_get_dns`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_arguments` | `InvalidParams` | Invalid ASCII DNS owner syntax, label/name length, or empty type list |
| `dns_response_failed` | `ServiceUnavailable` | Failure RCODE or TC after retries/fallback; carries type, resolver, status, truncation and recovery |

Note: NXDOMAIN (`Status: 3`) is **not** an error — returned as `nxdomain: true` in the result.

### `whois_lookup_ip`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_ip` | `ValidationError` | Input is not a complete valid IPv4, IPv6, or CIDR token |
| `private_range` | `ValidationError` | The numeric address falls within the explicit exclusion policy below |
| `ip_not_found` | `NotFound` | RIR RDAP returned 404 — no netblock record for this address |
| `ip_no_rdap_route` | `NotFound` | Successful IANA bootstrap has no covering route; explicitly not retryable |
| `invalid_arguments` | `InvalidParams` | IP/CIDR input fails conservative serialized syntax |

### `whois_lookup_asn`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_asn` | `ValidationError` | The whole trimmed token is not a decimal ASN in 1–4294967295 with the supported optional prefix/sign |
| `asn_not_found` | `NotFound` | RDAP returned 404 — ASN not found in any RIR |
| `invalid_arguments` | `InvalidParams` | ASN input fails serialized spelling grammar |

### `whois_get_dossier`

| reason | code | when |
|:-------|:-----|:-----|
| `invalid_arguments` | `InvalidParams` | Input does not match serialized registration-name syntax |
| `both_legs_failed` | `ServiceUnavailable` | Both RDAP and DoH legs failed — no data returned |

Note: single-leg failures are partial results (`source_error` on the failed leg), not thrown errors.

---

## Domain Mapping

### Nouns × Operations → API Endpoints

| Noun | Operations | RDAP Path | DoH Path |
|:-----|:-----------|:----------|:---------|
| Domain | lookup, record status | `GET https://<tld-rdap>/domain/<name>` | — |
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

Both legs run in parallel. A failed RDAP leg sets `rdap_coverage` and `registered` to null with `rdap_source_error`. A failed DoH leg sets `dns_nxdomain` to null with `dns_source_error`. A registry 404 remains record-absence data; if both legs fail operationally, throw `ServiceUnavailable`.

### `whois_lookup_ip` — primary registry lookup, then optional observations

| # | Call | Purpose |
|:--|:-----|:--------|
| 1 | RDAP IP lookup (IANA IP bootstrap → RIR RDAP server) | Netblock, org, CIDR, abuse contact |
| 2 | DoH PTR (`<reversed>.in-addr.arpa`) | Reverse DNS hostname |
| 2, opt-in | RIPEstat Network Info for the parsed base address, in parallel with PTR | Separately attributed observed prefix and all origin ASNs |

PTR is best-effort: `found` with hostname, `not_found` with null for successful absence, or `failed` with null and `ptr_source_error`. Cancellation propagates. The owner-matched CNAME chain allows at most five transitions under one total DNS deadline; unrelated owners are ignored.

`include_routing` defaults false. Enabled calls add nested `routing` status, prefix, all AS-prefixed `origin_asns`, source, snapshot basis and a `whois_lookup_asn` pointer. RIS observations use eight-hour dumps and never replace registry ownership/CIDRs. A valid empty prefix/ASN array is `not_found`; malformed/error envelopes, HTTP errors and deadline expiry are `failed` with error/recovery detail. One request has a fixed 3000 ms total deadline including body parsing, no retries and no ASN-detail fan-out. No new configuration is needed. Failed primary RDAP starts neither PTR nor routing; optional routing failure retains primary/PTR data and caller cancellation propagates.

---

## Design Decisions

### Registration status and unknown evidence

RDAP object absence cannot establish registration eligibility: reserved names and registry policy are outside this source. Keep the tool name, but never emit `available: true`. ICANN-only suffix recognition rejects known subdomains without querying their parent; an unrecognized suffix retains IANA handling. Private suffixes are hosting boundaries, not registry boundaries.

Validate primary domain objects before making record-presence claims: reject non-objects, arrays, error envelopes, absent/mismatched identity and explicitly wrong object classes. Case and equivalent IDNA names match; omitted class and optional registration fields remain compatible with sparse name-only records. `rdap_invalid_domain_response` is a non-retryable source failure, never registered or missing-record data; dossiers preserve successful DNS alongside it.

Registrant organization comes from jCard `org`, not personal `fn`. Preserve public org alongside explicit contact redaction, and omit placeholders. Privacy is `true` only with registrant-scoped redaction entries, remarks or known exact placeholders; otherwise it is unknown. DNSSEC preserves only explicit `secureDNS.delegationSigned`; missing fields, no coverage and failed legs stay null rather than implying false.

### Optional registrar authority

`include_registrar` defaults false to preserve the registry-only latency and dependency path. When enabled, follow one related RDAP link with no referral retries or recursion, at most five destination-checked redirects, and a total `RDAP_TIMEOUT_MS` deadline. The initial URL must be HTTPS without credentials; literal, mapped and DNS-resolved non-global targets are rejected. These checks are best-effort against DNS rebinding, not pinned-connection isolation. Matching-domain contact evidence stays in `registrar_detail`; registry dates, status, nameservers and DNSSEC are never merged with it. Failed optional detail retains the primary record, while caller cancellation propagates.

### Complete allocation and DNS data

Preserve every provider CIDR in order; `cidr` is populated only for one component so it never misrepresents part of an allocation as the whole. Missing extensions produce no invented prefix.

Only untruncated NOERROR and NXDOMAIN replies are consumable DNS data. A resolver failure can use the fallback, but CAA never repeats the same fallback resolver. TXT values use fences longer than any embedded backtick run, retaining whitespace, duplicates and empty values. Fences preserve presentation, not a prompt-injection boundary.

NXDOMAIN refers to the terminal name when aliases precede it; preserve supported answer records and resolver attribution. PTR still stops at NXDOMAIN without following those aliases. Dossier MX normalization preserves the null exchange `0 .` and labels its explicit no-mail meaning independently of unknown/absent MX evidence; it assigns no provider.

Render RDAP provider strings literally when Markdown could reinterpret punctuation or whitespace. Content-sized fences preserve newlines, repeated/edge spaces and backticks; ordinary text stays compact. Structured values are unchanged. This is presentation fidelity, not a script-execution or injection boundary.

### Serialized identifier grammar

Registration names use ASCII hostname labels with 63/253-character bounds; DNS names separately allow underscore labels and one terminal root dot with the same normalized bounds. Shared patterns drive runtime syntax and advertised JSON Schema. ASN and IP/CIDR patterns are conservative and impose no arbitrary length ceiling: zero-padding and accepted whitespace survive. Syntax rejections use `InvalidParams`/`invalid_arguments`; complete address parsing, prefix ranges, numeric ASN bounds and exclusion policy remain semantic typed errors.

### IP lookup exclusions

The server excludes exactly IPv4 `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `255.0.0.0/8`, and IPv6 `::1/128`, `fc00::/7`, `fe80::/10`, by numeric address. IPv4-mapped IPv6 follows the embedded IPv4 policy. These exclusions preserve the server's lookup policy; they do not imply that registries lack reservation records. TEST-NET, multicast, documentation IPv6, `::`, and `::10` remain eligible, with outcomes determined by bootstrap coverage and registry responses.

CIDR queries look up the supplied base address, without masking it to a network boundary. The output `ip` preserves the query. Parsing and policy precede every network call.

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

### CAA record format and the fallback resolver

**Decision:** Cloudflare is the primary DoH resolver. NextDNS (`https://dns.nextdns.io`) answers CAA queries and is the fallback for every other type.

**Reasoning:** Cloudflare DoH returns CAA records as raw hex wire format (`\# 19 00 05 69 73 73 75 65...`). NextDNS speaks the same `application/dns-json` format and returns CAA data as human-readable text (`0 issue "letsencrypt.org"`), so no wire-format decoder is needed. Google DoH (`dns.google`) filled this role first, but Google's terms prohibit using it as a relay for third-party queries.

### No resources or prompts

**Decision:** No MCP resources or prompts defined.

**Reasoning:** All data is query-driven with no stable URI addressing — you can't address a domain's RDAP record by a URI that means anything across sessions. Prompts would add no value: the tools are self-sufficient and the use cases (lookup, check, fetch) don't benefit from a reusable message template.

### `whois_get_dossier` includes factual signals, not scores

**Decision:** Dossier surfaces `age_days`, `privacy_redacted`, `registrar`, `ns_provider`, `mx_provider` as discrete fields. No composite score.

**Reasoning:** A fabricated threat score built from arbitrary weights is epistemically empty and misleads both agents and humans. The dossier gives the inputs; the agent or human analyst decides the verdict. Surfacing the components lets the agent chain into nist-nvd, attack-surface, or threat-intel servers for enrichment.

---

## Known Limitations

- **Privacy evidence varies.** Explicit registrant redaction is surfaced as true; absent evidence remains null. A public organization can coexist with redacted contact fields, and missing fields alone prove neither redaction nor its absence.
- **RDAP coverage gaps.** Some ccTLDs lack RDAP entirely. The server returns `rdap_coverage: false` in these cases; WHOIS-43 fallback is deferred (see Design Decisions).
- **Rate limits vary by registry.** The service layer retries transient failures with backoff, but sustained bulk lookups may hit registry limits. Exhausted HTTP 429 responses surface `RateLimited` with retry metadata.
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

A `404` response establishes that the queried RDAP object was not found. It does not establish registration eligibility. `whois_check_availability` returns `not_found` and `available: null`; a found object returns `registered` and `available: false`.

### DoH response shape (Cloudflare)

`GET https://cloudflare-dns.com/dns-query?name=<domain>&type=<TYPE>` with `Accept: application/dns-json`

- `Status: 0` = `NOERROR`, `Status: 3` = `NXDOMAIN` (terminal resolution name does not exist; preceding aliases remain data)
- `Answer[]`: `{ name, type (numeric), TTL, data (string) }`
- `Authority[]`: present on NXDOMAIN/NOERROR-with-no-records (SOA of the zone)
- DNS type numbers: A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, AAAA=28, CAA=257

**CAA quirk:** Cloudflare returns CAA `data` as raw hex wire format (`\# 19 00 05 ...`). NextDNS returns human-readable (`0 issue "letsencrypt.org"`), so CAA queries go to NextDNS.

**PTR (reverse DNS):** construct query name as `<reversed-octets>.in-addr.arpa` (IPv4) or `<nibble-reversed>.ip6.arpa` (IPv6).

### DoH rate limits

Cloudflare DoH is a public resolver with no documented rate limit for reasonable use; NextDNS carries only CAA queries and fallback traffic. The framework's `withRetry` handles transient failures.

### RDAP rate limits

Per-registry: Verisign (`.com`/`.net`) — no documented limit, liberal in practice. RIRs (ARIN, RIPE, APNIC, etc.) — no published limit but enforce per-IP throttling. Retry on 429 with exponential backoff (base 2s for rate-limited responses).
