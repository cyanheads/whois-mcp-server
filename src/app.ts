/**
 * @fileoverview whois-mcp-server application wiring — the `createApp()` options
 * the entry point starts and tests assert against.
 * @module app
 */

import type { CreateAppOptions } from '@cyanheads/mcp-ts-core';
import { whoisCheckAvailability } from './mcp-server/tools/definitions/whois-check-availability.tool.js';
import { whoisGetDns } from './mcp-server/tools/definitions/whois-get-dns.tool.js';
import { whoisGetDossier } from './mcp-server/tools/definitions/whois-get-dossier.tool.js';
import { whoisLookupAsn } from './mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupDomain } from './mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import { whoisLookupIp } from './mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { initDohService } from './services/doh/doh-service.js';
import { initRdapService } from './services/rdap/rdap-service.js';

export const appOptions = {
  name: 'whois-mcp-server',
  title: 'whois-mcp-server',
  /**
   * No per-session state, and no handler calls `ctx.requestInput` — the session
   * store and the per-session `McpServer` allocation are pure overhead, and the
   * process scales horizontally without them. Declared here so the posture holds
   * however the server is launched; a deployment's `MCP_SESSION_MODE` still wins
   * when it carries a meaningful value.
   */
  sessionMode: 'stateless',
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
} satisfies CreateAppOptions;
