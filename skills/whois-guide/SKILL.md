---
name: whois-guide
description: Investigate a hostname or trace a DNS address to its registry allocation and observed origin ASNs with whois_* tools. Use when registration, DNS, and routing evidence may refer to different names or organizations.
license: Apache-2.0
metadata:
  author: "cyanheads"
  version: "1.0"
---

## Scope

Keyless lookups across domain and regional Internet registries, DNS-over-HTTPS, and RIPE RIS routing observations. Use the evidence for the specific name, address, or ASN that each source queried.

## Identifiers

- A dossier's `registration_domain`, when present, is the subject of its registration section. Otherwise use `domain`. Use the dossier's ASCII `domain` for follow-up DNS calls. `unicode_domain` is for display.
- In `whois_get_dns`, `records[].name` identifies the answer owner. A CNAME's `data` names its target. An A or AAAA answer's `data` supplies an address for `whois_lookup_ip`.
- In `whois_lookup_ip`, each `routing.origin_asns` entry identifies an observed origin to resolve with `whois_lookup_asn`.

## Gates

- Before reporting a registration result, check which name the registry queried and whether it returned a valid record or a 404. Missing RDAP coverage and source failures leave registration unknown. A 404 establishes record absence for that subject. Registration eligibility requires separate evidence.
- Before treating an empty dossier section as evidence of absence, check `rdap_source_error` and `dns_source_error`. Keep evidence from the successful leg. Preserve unknown privacy and DNSSEC values. DS and DNSKEY answers alone do not establish successful DNSSEC validation.
- Before assigning a DNS answer to a hostname, check its owner and follow the relevant alias chain. With NXDOMAIN after a CNAME, report the missing terminal name and preserve the preceding alias evidence. For a mixed-type lookup, use `query_sources` for resolver attribution. Query a type separately if the aggregate NXDOMAIN flag leaves its outcome ambiguous.
- Before resolving an origin ASN, check that routing returned `found`. An empty observation and a source failure have different meanings. Neither establishes that a prefix is unrouted. Keep RIS snapshot observations, ASN registration, IP allocation, and PTR evidence separately attributed.

## Workflows

**Investigate a hostname.** Start with `whois_get_dossier` when the task calls for both registration and DNS. To expand a found registration record, pass its registration subject to `whois_lookup_domain`. Use the original hostname when the task calls for an exact check, even if a dossier leg failed. If an exact lookup or registry-status check supplies a registrable-parent hint, query that parent separately when relevant and label its result with the parent name. For registrar contact details, opt into the registrar referral and attribute those details to the registrar.

**Trace a DNS address.** Fetch A and AAAA with `whois_get_dns`. Starting at the queried owner, match CNAME answer owners to the current name and follow their targets, comparing DNS names case-insensitively and ignoring a terminal root dot. Use only A or AAAA answers owned by the resulting name. If an alias target has no address in the response and the terminal name's absence has not been established, query that target directly. Pass the relevant address to `whois_lookup_ip`. Opt into routing when the task asks who originates the route, then resolve each relevant returned origin ASN. Report every observed origin for the address, even if only some of their registry records resolve.

**Check mail or DNS service.** Treat the dossier's first-record provider labels as hints. Inspect the DNS records for the service in question. A null MX (`0 .`) explicitly signals that the name accepts no mail. An empty MX result does not convey that signal.
