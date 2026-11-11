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
  skills: 'skills',
  instructions:
    'Keyless RDAP and DNS-over-HTTPS lookups. Use whois_lookup_domain for an exact registry record or whois_get_dossier for combined registration and DNS triage. A dossier can attribute registration to a parent while DNS stays on the queried name. RDAP record absence does not establish eligibility, and missing coverage, failed sources, or absent DNSSEC and privacy evidence leave those findings unknown. For routing, opt in on whois_lookup_ip and pass returned origin ASNs to whois_lookup_asn. Attribute RIS observations separately from registry allocation.',
  setup(core) {
    getServerConfig();
    initRdapService(core.config, core.storage);
    initDohService(core.config, core.storage);
    initRoutingService(core.config, core.storage);
  },
} satisfies CreateAppOptions;
