/**
 * @fileoverview whois-mcp-server application wiring — the `createApp()` options
 * the entry point starts and tests assert against.
 * @module app
 */

import type { CreateAppOptions } from '@cyanheads/mcp-ts-core';
import { getServerConfig } from './config/server-config.js';
import { whoisCheckAvailability } from './mcp-server/tools/definitions/whois-check-availability.tool.js';
import { whoisGetDns } from './mcp-server/tools/definitions/whois-get-dns.tool.js';
import { whoisGetDossier } from './mcp-server/tools/definitions/whois-get-dossier.tool.js';
import { whoisLookupAsn } from './mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupDomain } from './mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import { whoisLookupIp } from './mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { initDohService } from './services/doh/doh-service.js';
import { initRdapService } from './services/rdap/rdap-service.js';
import { initRoutingService } from './services/routing/routing-service.js';

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
    '- whois_lookup_domain: registry record; include_registrar opts into separate registrar contact detail\n' +
    '- whois_check_availability: registered/not_found/unknown RDAP record status; absence does not establish registration eligibility\n' +
    '- whois_get_dns: ASCII DNS owner names, including underscores and one root dot (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR)\n' +
    '- whois_lookup_ip: IP/CIDR ownership and PTR; include_routing adds RIS-observed prefix/origin ASNs for whois_lookup_asn, separate from ownership\n' +
    '- whois_lookup_asn: ASN to org/RIR resolution\n' +
    '- whois_get_dossier: domain triage with partial source errors; absent DNSSEC/privacy evidence stays unknown',
  setup(core) {
    getServerConfig();
    initRdapService(core.config, core.storage);
    initDohService(core.config, core.storage);
    initRoutingService(core.config, core.storage);
  },
} satisfies CreateAppOptions;
