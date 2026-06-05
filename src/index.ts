#!/usr/bin/env node
/**
 * @fileoverview whois-mcp-server MCP server entry point.
 * @module index
 */

import { createApp } from '@cyanheads/mcp-ts-core';
import { whoisCheckAvailability } from './mcp-server/tools/definitions/whois-check-availability.tool.js';
import { whoisGetDns } from './mcp-server/tools/definitions/whois-get-dns.tool.js';
import { whoisGetDossier } from './mcp-server/tools/definitions/whois-get-dossier.tool.js';
import { whoisLookupAsn } from './mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupDomain } from './mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import { whoisLookupIp } from './mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { initDohService } from './services/doh/doh-service.js';
import { initRdapService } from './services/rdap/rdap-service.js';

await createApp({
  tools: [
    whoisLookupDomain,
    whoisCheckAvailability,
    whoisGetDns,
    whoisLookupIp,
    whoisLookupAsn,
    whoisGetDossier,
  ],
  resources: [],
  prompts: [],
  instructions:
    'whois-mcp-server: domain and IP intelligence via RDAP and DNS-over-HTTPS. No API keys required.\n' +
    '- whois_lookup_domain: full registration record (registrar, dates, status, nameservers)\n' +
    '- whois_check_availability: is a domain available to register? (RDAP 404 = available)\n' +
    '- whois_get_dns: DNS records for any hostname (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR)\n' +
    '- whois_lookup_ip: IP/CIDR netblock, org, abuse contact, and PTR via RIR RDAP\n' +
    '- whois_lookup_asn: ASN to org/RIR resolution\n' +
    '- whois_get_dossier: one-call domain triage — registration + DNS in parallel with inferred signals',
  setup(core) {
    initRdapService(core.config, core.storage);
    initDohService(core.config, core.storage);
  },
});
