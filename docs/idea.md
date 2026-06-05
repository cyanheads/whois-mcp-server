---
name: whois-mcp-server
description: "WHOIS, RDAP, and DNS in one normalized surface — domain registration, availability, DNS records, and IP ownership without per-registry format wrangling."
version: 0.0.0
status: idea
category: developer-tooling
hosted: false
subdomain: ""
port: 0
tools: 0
resources: 0
prompts: 0
rating: unrated
stars: 0
open_issues: 0
auth: none
framework: mcp-ts-core
core_version: ""
npm: "@cyanheads/whois-mcp-server"
created: 2026-05-30
error_handling: unaudited
response_enrichment: unaudited
needs_migration: false
pattern: multi-source aggregation (RDAP + WHOIS-43 + DoH)
complexity: medium
api-deps: RDAP (IANA bootstrap → registry/RIR RDAP servers), WHOIS port 43, DNS-over-HTTPS (Cloudflare/Google)
api-cost: free (RDAP / WHOIS / DoH all keyless; rate-limited per registry)
hostable: true
composes-with: nist-nvd-mcp-server, attack-surface-mcp-server, threat-intel-mcp-server
---

# whois-mcp-server

Domain and IP intelligence with one normalized shape. The reason this beats `curl` isn't access — it's that the access is a mess: classic WHOIS is unstructured, registry-specific free-text (every TLD formats its output differently), RDAP is the structured IETF successor but you must bootstrap through IANA to find the right RDAP server per TLD/IP, and DNS lives on a separate path entirely. The server hides all of it: RDAP-first with auto-bootstrap, port-43 WHOIS fallback with the free-text parsed into the same schema, DNS over HTTPS, and IP → RIR lookups — the agent gets a clean record regardless of TLD.

**Audience:** Developers, ops/SRE, and security/threat-triage. "Who owns this domain, when does it expire, what does it resolve to, who runs this IP" is daily work across all three.

## User Goals

- Look up a domain's registration: registrar, created/updated/expires, nameservers, status codes, DNSSEC
- Check whether a domain is registered or available
- Get DNS records for a domain (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA)
- Look up an IP's network owner, ASN, country, and abuse contact
- Reverse-DNS an IP
- Pull a one-call domain dossier (registration + DNS + factual signals) for triage

## Sources (service layer)

Each source is its own service; tools compose across them — the agent sees "domain intelligence," not "RDAP + WHOIS + DoH."

| Source | Provides | Transport | Auth |
|:-------|:---------|:----------|:-----|
| RDAP (IANA bootstrap → registry/RIR) | Structured registration for domains and IPs; the modern path | HTTPS/JSON | None |
| WHOIS (port 43, per-TLD servers) | Fallback for TLDs with thin RDAP coverage; free-text parsed to schema | Raw TCP/43 | None |
| DNS-over-HTTPS (1.1.1.1 / 8.8.8.8) | A/AAAA/MX/TXT/NS/CNAME/SOA/CAA records | HTTPS | None |
| RIR RDAP (ARIN/RIPE/APNIC/LACNIC/AFRINIC) | IP/CIDR → netblock, org, ASN, abuse contact | HTTPS/JSON | None |

## Tool Surface (sketch)

```
whois_lookup_domain      — the flagship. Domain → normalized registration record:
                           registrar, created/updated/expires dates, registrant org
                           (where not redacted), EPP status codes, nameservers,
                           DNSSEC. RDAP first (auto-bootstrapped via IANA), port-43
                           WHOIS fallback with free-text parsed to the same schema.
                           One shape regardless of TLD.

whois_check_availability — is this domain registered or available? Fast yes/no, plus
                           expiry date and registrar when registered. For "can I
                           register X" and bulk name checks.

whois_get_dns    — DNS records for a domain over DoH: A, AAAA, MX, TXT, NS,
                           CNAME, SOA, CAA. types[] selects which. Returns records
                           with TTLs. The companion to registration — "what does this
                           domain actually resolve to."

whois_lookup_ip          — IP or CIDR → network owner via RIR RDAP (ARIN/RIPE/APNIC/
                           LACNIC/AFRINIC, auto-routed): netblock, org, country, ASN,
                           abuse contact, plus reverse DNS (PTR). "Who owns this IP?"

whois_lookup_asn         — ASN number (e.g. AS15169) → org name, country, registered
                           netblocks, and RIR source. Distinct from whois_lookup_ip
                           (input is an ASN, not an IP); ops and security users pull
                           ASNs from BGP tables and threat intel and need to resolve
                           them directly. Same RIR RDAP path, different entry point.

whois_get_dossier        — workflow: domain → registration + DNS + factual signals in
                           one call (age in days, privacy-redacted?, registrar, NS
                           provider, mail provider inferred from MX). The "tell me
                           everything about this domain" dossier; triage-oriented.
```

## Design Notes

- **The moat is normalization.** RDAP bootstrap (IANA → per-TLD / per-RIR RDAP server) + free-text WHOIS parsing into one schema + a unified DNS path. Agents otherwise juggle the IANA bootstrap registry, dozens of TLD-specific WHOIS text formats, and a separate DNS library.
- **RDAP-first, WHOIS-43 fallback — and that split has a hosting consequence.** RDAP and DoH are HTTPS/JSON (work on Cloudflare Workers, the framework's Workers target); port-43 WHOIS is raw TCP (Node-only). The Workers build is RDAP + DoH only and degrades gracefully where RDAP coverage is thin (some ccTLDs). Document the runtime split.
- **Privacy redaction is the norm now** (GDPR/ICANN) — registrant fields are frequently redacted. Surface "redacted" explicitly rather than implying the data is missing or unknown.
- **No synthesized risk score.** Surface factual signals (domain age, privacy flag, registrar, NS/MX provider) and let the agent judge. A fabricated "threat score" built from arbitrary weights is exactly the kind of empty signal to avoid — the dossier gives the inputs, not a verdict.
- Cache aggressively (registration data changes slowly) and back off per-registry; rate limits are uneven across registries/RIRs.
- **Naming.** Scope includes DNS + IP, broader than the literal "whois." Kept `whois-mcp-server` because that's the term people search for; `domain-intel-mcp-server` is the alternative if signaling DNS/IP inclusion matters more than recognizability. Open question for build time — see chat.
- Composes with `nist-nvd` and the `attack-surface` / `threat-intel` security ideas (domain age + ownership + DNS are standard indicator-enrichment inputs).
- README one-liner: "WHOIS, RDAP, and DNS in one normalized surface — domain registration, availability, records, and IP ownership without the per-registry format wrangling."
