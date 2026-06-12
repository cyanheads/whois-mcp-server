/**
 * @fileoverview whois_lookup_ip tool — IP address / CIDR lookup via RIR RDAP with PTR reverse DNS.
 * @module mcp-server/tools/definitions/whois-lookup-ip.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getDohService } from '@/services/doh/doh-service.js';
import { getRdapService, ipv4ToPtr, ipv6ToPtr, validateIp } from '@/services/rdap/rdap-service.js';

export const whoisLookupIp = tool('whois_lookup_ip', {
  title: 'IP Address / Network Lookup',
  description:
    'Look up an IP address or CIDR block via RIR RDAP (ARIN, RIPE, APNIC, LACNIC, AFRINIC — auto-routed ' +
    'via IANA bootstrap). Returns netblock, org, country, CIDR, abuse contact email, and reverse DNS (PTR) ' +
    'via DoH. PTR is best-effort — failure returns ptr: null. Private/reserved ranges (RFC 1918, loopback, ' +
    'link-local) return a validation error — no RIR RDAP record exists for them.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    ip: z
      .string()
      .describe(
        'IPv4 address (e.g., "8.8.8.8"), IPv6 address (e.g., "2001:4860:4860::8888"), or CIDR notation ' +
          '(e.g., "192.0.2.0/24"). Private/reserved ranges will return a validation error.',
      ),
  }),

  output: z.object({
    ip: z.string().describe('The IP or CIDR queried.'),
    handle: z.string().optional().describe('RIR handle / object identifier.'),
    start_address: z.string().optional().describe('Start address of the IP netblock.'),
    end_address: z.string().optional().describe('End address of the IP netblock.'),
    cidr: z.string().optional().describe('CIDR notation of the netblock (e.g., "8.8.8.0/24").'),
    ip_version: z.string().optional().describe('IP version: "v4" or "v6".'),
    name: z.string().optional().describe('Network name assigned by the RIR.'),
    type: z.string().optional().describe('Network type (e.g., "DIRECT ALLOCATION").'),
    country: z
      .string()
      .optional()
      .describe('Country code (ISO 3166-1 alpha-2). Omitted when not in RDAP data.'),
    org_name: z.string().optional().describe('Organization name holding the netblock.'),
    abuse_email: z.string().optional().describe('Abuse contact email address.'),
    ptr: z
      .string()
      .nullable()
      .describe(
        'Reverse DNS hostname (PTR record). Null when PTR lookup fails, returns no answer, or domain is NXDOMAIN.',
      ),
    rdap_source: z
      .string()
      .optional()
      .describe('RIR that provided the RDAP data (ARIN, RIPE, APNIC, LACNIC, AFRINIC).'),
  }),

  errors: [
    {
      reason: 'invalid_ip',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Input is not a valid IPv4, IPv6, or CIDR address.',
      recovery:
        'Provide a valid IPv4 (e.g., "8.8.8.8"), IPv6 (e.g., "2001:db8::1"), or CIDR (e.g., "192.0.2.0/24").',
    },
    {
      reason: 'private_range',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Input is a private or reserved range — no RIR RDAP record exists for it.',
      recovery:
        'Use a public, globally-routable IP address. RFC 1918, loopback, and link-local addresses have no RIR records.',
    },
    {
      reason: 'ip_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'RIR RDAP returned 404 — no netblock record for this address.',
      recovery:
        'The IP address is not found in any RIR RDAP database. Try a different IP or verify it is globally routable.',
    },
  ],

  async handler(input, ctx) {
    const { valid } = validateIp(input.ip);
    if (!valid) {
      throw ctx.fail('invalid_ip', `"${input.ip}" is not a valid IPv4, IPv6, or CIDR address.`, {
        ...ctx.recoveryFor('invalid_ip'),
      });
    }

    ctx.log.info('RDAP IP lookup', { ip: input.ip });

    // getRdapService().lookupIp already throws invalid_ip / private_range via factories with data.reason
    const network = await getRdapService().lookupIp(input.ip, ctx);

    // PTR lookup — best-effort, failure = null
    const base = input.ip.split('/')[0] ?? '';
    const isIpv6 = base.includes(':');
    const ptrName = isIpv6 ? ipv6ToPtr(base) : ipv4ToPtr(base);
    const ptr = await getDohService().ptrLookup(ptrName, ctx);

    return { ...network, ptr };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# IP: ${result.ip}`);
    if (result.rdap_source) lines.push(`**RIR Source:** ${result.rdap_source}`);
    if (result.org_name) lines.push(`**Organization:** ${result.org_name}`);
    if (result.cidr) lines.push(`**CIDR:** ${result.cidr}`);
    if (result.start_address && result.end_address) {
      lines.push(`**Range:** ${result.start_address} — ${result.end_address}`);
    }
    if (result.name) lines.push(`**Network Name:** ${result.name}`);
    if (result.type) lines.push(`**Type:** ${result.type}`);
    if (result.ip_version) lines.push(`**IP Version:** ${result.ip_version}`);
    if (result.country) lines.push(`**Country:** ${result.country}`);
    if (result.handle) lines.push(`**Handle:** ${result.handle}`);
    if (result.abuse_email) lines.push(`**Abuse Email:** ${result.abuse_email}`);
    lines.push(`**Reverse DNS (PTR):** ${result.ptr ?? 'Not available'}`);

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
