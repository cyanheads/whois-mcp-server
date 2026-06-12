/**
 * @fileoverview whois_lookup_asn tool — ASN to org/RIR resolution via RIR RDAP.
 * @module mcp-server/tools/definitions/whois-lookup-asn.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getRdapService } from '@/services/rdap/rdap-service.js';

export const whoisLookupAsn = tool('whois_lookup_asn', {
  title: 'ASN Lookup',
  description:
    'Resolve an Autonomous System Number (ASN) to its org name, country, and RIR source via RIR RDAP. ' +
    'Accepts AS-prefixed format (e.g., "AS15169") or bare integer (e.g., "15169"). Distinct from IP ' +
    'lookup — the entry point is the ASN itself, not an IP within its block.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    asn: z
      .string()
      .describe(
        'Autonomous System Number to look up. Accepts AS-prefixed format (e.g., "AS15169") or bare ' +
          'integer (e.g., "15169").',
      ),
  }),

  output: z.object({
    asn: z.string().describe('Normalized ASN identifier (AS-prefixed, e.g., "AS15169").'),
    handle: z.string().optional().describe('RIR handle / object identifier.'),
    start_autnum: z.number().optional().describe('Start ASN of the registered range.'),
    end_autnum: z.number().optional().describe('End ASN of the registered range.'),
    name: z.string().optional().describe('ASN network name.'),
    type: z.string().optional().describe('ASN type (e.g., "DIRECT ALLOCATION").'),
    country: z
      .string()
      .optional()
      .describe('Country code (ISO 3166-1 alpha-2). Omitted when not in RDAP data.'),
    org_name: z.string().optional().describe('Organization name registered for this ASN.'),
    rir: z
      .string()
      .optional()
      .describe(
        'Regional Internet Registry that manages this ASN (ARIN, RIPE, APNIC, LACNIC, AFRINIC).',
      ),
  }),

  errors: [
    {
      reason: 'invalid_asn',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Input does not match AS<number> or bare integer format.',
      recovery: 'Provide a valid ASN like "AS15169" or "15169". Numbers must be positive integers.',
    },
    {
      reason: 'asn_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'RDAP returned 404 — ASN not found in any RIR.',
      recovery:
        'The ASN is not found in any RIR RDAP database. Verify the ASN number is correct and assigned.',
    },
  ],

  async handler(input, ctx) {
    ctx.log.info('RDAP ASN lookup', { asn: input.asn });

    // Service throws invalid_asn / asn_not_found via factories with data.reason
    const record = await getRdapService().lookupAsn(input.asn, ctx);
    return record;
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# ASN: ${result.asn}`);
    if (result.org_name) lines.push(`**Organization:** ${result.org_name}`);
    if (result.rir) lines.push(`**RIR:** ${result.rir}`);
    if (result.name) lines.push(`**Network Name:** ${result.name}`);
    if (result.type) lines.push(`**Type:** ${result.type}`);
    if (result.country) lines.push(`**Country:** ${result.country}`);
    if (result.handle) lines.push(`**Handle:** ${result.handle}`);
    if (result.start_autnum !== undefined && result.end_autnum !== undefined) {
      if (result.start_autnum === result.end_autnum) {
        lines.push(`**ASN Range:** ${result.start_autnum}`);
      } else {
        lines.push(`**ASN Range:** ${result.start_autnum} — ${result.end_autnum}`);
      }
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
