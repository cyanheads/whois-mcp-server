/**
 * @fileoverview whois_check_availability tool — registry record status without an eligibility guarantee.
 * @module mcp-server/tools/definitions/whois-check-availability.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getRdapService } from '@/services/rdap/rdap-service.js';
import { REGISTRATION_NAME_PATTERN } from './_fqdn.js';
import { literal } from './_literal.js';

export const whoisCheckAvailability = tool('whois_check_availability', {
  title: 'Domain Registration Status',
  description:
    'Check RDAP registry record status: registered, not_found, or unknown when coverage is absent. ' +
    'available is false for a found record and null otherwise; a registry miss never guarantees registration eligibility. ' +
    'Known ICANN subdomains are rejected with their registrable parent; private suffixes are not registration boundaries. ' +
    'For the full record use whois_lookup_domain.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    domain: z
      .string()
      .max(253)
      .regex(
        REGISTRATION_NAME_PATTERN,
        'Provide a dot-separated ASCII hostname such as example.com; labels are 1–63 characters, without underscores, whitespace or a root dot.',
      )
      .describe(
        'Fully qualified domain name to check (e.g., "myfuturename.com"). ' +
          'Must be a valid FQDN — labels separated by dots.',
      ),
  }),

  output: z.object({
    domain: z.string().describe('Normalized domain name checked.'),
    registration_status: z
      .enum(['registered', 'not_found', 'unknown'])
      .describe(
        'Registry record present, absent, or RDAP coverage unavailable; never registration eligibility.',
      ),
    available: z
      .literal(false)
      .nullable()
      .describe(
        'False when a registration record exists; otherwise null. A registry miss never establishes availability.',
      ),
    rdap_coverage: z.boolean().describe('True when a RDAP server was found for this TLD.'),
    registrar: z.string().optional().describe('Registrar name when available: false.'),
    expiry_date: z.string().optional().describe('Expiry date when available: false.'),
  }),

  errors: [
    {
      reason: 'rdap_invalid_domain_response',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'The primary RDAP response is not a matching successful domain object.',
      recovery: 'Retry later when the registry returns a valid matching domain record.',
      retryable: false,
      thrownBy: 'service',
    },
    {
      reason: 'non_registrable_domain',
      code: JsonRpcErrorCode.ValidationError,
      when: 'An ICANN-recognized suffix identifies the query as a subdomain.',
      recovery:
        'Query the registrable parent named in the error instead; no eligibility is implied.',
      thrownBy: 'service',
    },
  ],

  async handler(input, ctx) {
    ctx.log.info('RDAP availability check', { domain: input.domain });

    const result = await getRdapService().checkAvailability(input.domain, ctx);

    if (result.registration_status !== 'registered') {
      return {
        domain: input.domain.toLowerCase(),
        available: null,
        registration_status: result.registration_status,
        rdap_coverage: result.rdap_coverage,
      };
    }

    // Registered
    return {
      domain: result.record.domain,
      available: false as const,
      registration_status: result.registration_status,
      rdap_coverage: true,
      registrar: result.record.registrar,
      expiry_date: result.record.expiry_date,
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# Domain: ${result.domain}`);

    lines.push(`**Registration Status:** ${result.registration_status}`);
    lines.push(
      `**Available:** ${result.available === false ? 'No — registered' : 'Unknown — RDAP record absence does not establish eligibility'}`,
    );
    lines.push(`**RDAP Coverage:** ${result.rdap_coverage ? 'Yes' : 'No'}`);

    if (result.registrar) lines.push(`**Registrar:** ${literal(result.registrar)}`);
    if (result.expiry_date) lines.push(`**Expires:** ${literal(result.expiry_date)}`);

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
