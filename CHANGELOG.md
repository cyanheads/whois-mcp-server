# Changelog

All notable changes to this project. Each entry links to its full per-version file in [changelog/](changelog/).

## [0.1.6](changelog/0.1.x/0.1.6.md) — 2026-09-30

Lookup inputs are validated whole before any request, DNS results attribute each query to its resolver, and the dossier renders every TXT record and labels providers by domain.

## [0.1.5](changelog/0.1.x/0.1.5.md) — 2026-09-20 · ⚠️ Breaking

Adopt mcp-ts-core 0.13.6 — the server resolves to a stateless session posture however it is launched, and an out-of-schema argument fails as InvalidParams (-32602) with a Recovery line instead of ValidationError (-32007). The Bun floor rises to 1.4.0.

## [0.1.4](changelog/0.1.x/0.1.4.md) — 2026-08-21

Adopt mcp-ts-core 0.12.3 (SDK v2 era) — strict tool inputs, error-envelope output schemas; IP/ASN RDAP 404s now reject as NotFound with recovery hints; supply-chain install guard

## [0.1.3](changelog/0.1.x/0.1.3.md) — 2026-06-12

Adopt mcp-ts-core 0.10.6 — server identity fields, Docker healthcheck; input-validation errors reclassified to ValidationError

## [0.1.2](changelog/0.1.x/0.1.2.md) — 2026-06-06

DoH fallback switched to NextDNS; domain_not_found recovery hint; description leaks removed; dead error contract cleaned up

## [0.1.1](changelog/0.1.x/0.1.1.md) — 2026-06-05 · 🛡️ Security

Initial public release — 6 RDAP + DoH tools for domain registration, availability, DNS records, IP netblock, ASN, and domain dossier; TXT record prompt-injection hardening
