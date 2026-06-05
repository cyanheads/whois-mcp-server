/**
 * @fileoverview whois_check_availability tool — domain availability check via RDAP 404 semantics.
 * @module mcp-server/tools/definitions/whois-check-availability.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getRdapService } from '@/services/rdap/rdap-service.js';
import { isValidFqdn } from './_fqdn.js';

export const whoisCheckAvailability = tool('whois_check_availability', {
  title: 'Domain Availability Check',
  description:
    'Check whether a domain name is registered or available for registration. RDAP 404 = available — ' +
    'this is the RDAP spec behavior, modeled as data (available: true) not an error. Returns available: false ' +
    'with registrar and expiry_date when the domain is registered. When the TLD has no RDAP coverage, returns ' +
    'available: null with rdap_coverage: false — availability cannot be determined. Designed for "can I register X" ' +
    'and bulk name sweeps. For the full registration record use whois_lookup_domain.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    domain: z
      .string()
      .describe(
        'Fully qualified domain name to check (e.g., "myfuturename.com"). ' +
          'Must be a valid FQDN — labels separated by dots.',
      ),
  }),

  output: z.object({
    domain: z.string().describe('Normalized domain name checked.'),
    available: z
      .boolean()
      .nullable()
      .describe(
        'True = available for registration (RDAP 404). False = registered. ' +
          'Null = rdap_coverage is false — cannot determine availability for this TLD.',
      ),
    rdap_coverage: z.boolean().describe('True when a RDAP server was found for this TLD.'),
    registrar: z.string().optional().describe('Registrar name when available: false.'),
    expiry_date: z.string().optional().describe('Expiry date when available: false.'),
  }),

  errors: [
    {
      reason: 'invalid_domain',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'Input is not a valid FQDN.',
      recovery:
        'Provide a valid fully-qualified domain name like "example.com" or "sub.example.org".',
    },
    {
      reason: 'rdap_no_coverage',
      code: JsonRpcErrorCode.NotFound,
      when: 'TLD has no RDAP server — available is null, cannot determine registration status.',
      recovery:
        'This TLD has no RDAP coverage; availability cannot be determined programmatically.',
    },
  ],

  async handler(input, ctx) {
    if (!isValidFqdn(input.domain)) {
      throw ctx.fail('invalid_domain', `"${input.domain}" is not a valid FQDN.`, {
        ...ctx.recoveryFor('invalid_domain'),
      });
    }

    ctx.log.info('RDAP availability check', { domain: input.domain });

    const result = await getRdapService().checkAvailability(input.domain, ctx);

    if (result.available === null) {
      // No RDAP coverage — surface as data, not an error
      return {
        domain: input.domain.toLowerCase(),
        available: null,
        rdap_coverage: false,
      };
    }

    if (result.available === true) {
      return {
        domain: input.domain.toLowerCase(),
        available: true,
        rdap_coverage: true,
      };
    }

    // Registered
    return {
      domain: result.record.domain,
      available: false,
      rdap_coverage: true,
      registrar: result.record.registrar,
      expiry_date: result.record.expiry_date,
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# Domain: ${result.domain}`);

    if (result.available === null) {
      lines.push(`**Available:** Unknown (no RDAP coverage for this TLD)`);
      lines.push(`**RDAP Coverage:** No`);
    } else if (result.available === true) {
      lines.push(`**Available:** Yes — not currently registered`);
      lines.push(`**RDAP Coverage:** Yes`);
    } else {
      lines.push(`**Available:** No — registered`);
      lines.push(`**RDAP Coverage:** Yes`);
    }

    if (result.registrar) lines.push(`**Registrar:** ${result.registrar}`);
    if (result.expiry_date) lines.push(`**Expires:** ${result.expiry_date}`);

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
