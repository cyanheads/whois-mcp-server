/**
 * @fileoverview whois_lookup_domain tool — domain registration lookup via RDAP with IANA bootstrap.
 * @module mcp-server/tools/definitions/whois-lookup-domain.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getRdapService } from '@/services/rdap/rdap-service.js';

/** Simple FQDN validation: labels separated by dots, no consecutive dots, length limits */
function isValidFqdn(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  const labels = domain.split('.');
  if (labels.length < 2) return false;
  return labels.every((label) => {
    if (!label || label.length > 63) return false;
    return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$/.test(label);
  });
}

export const whoisLookupDomain = tool('whois_lookup_domain', {
  title: 'Domain Registration Lookup',
  description:
    "Look up a domain's registration record — registrar, created/expiry dates, nameservers, EPP status codes, " +
    'DNSSEC flag, and registrant org (where not privacy-redacted). Uses RDAP via IANA bootstrap to auto-select ' +
    'the correct per-TLD RDAP server, returning one normalized shape regardless of TLD. When the TLD has no RDAP ' +
    'coverage, returns rdap_coverage: false. RDAP 404 (domain not registered) throws domain_not_found — use ' +
    'whois_check_availability instead if you want to test registration status without an error.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    domain: z
      .string()
      .describe(
        'Fully qualified domain name to look up (e.g., "example.com", "github.com"). ' +
          'Must be a valid FQDN — labels separated by dots, each label up to 63 chars.',
      ),
  }),

  output: z.object({
    domain: z.string().describe('Normalized domain name (lowercased).'),
    rdap_coverage: z
      .boolean()
      .describe(
        'True when a RDAP server was found for this TLD; false when RDAP coverage is absent.',
      ),
    handle: z
      .string()
      .optional()
      .describe('Registry handle / object identifier assigned by the registry.'),
    registrar: z.string().optional().describe('Name of the sponsoring registrar.'),
    registrar_iana_id: z.string().optional().describe('IANA registrar ID number.'),
    created_date: z.string().optional().describe('ISO 8601 domain registration date.'),
    updated_date: z
      .string()
      .optional()
      .describe('ISO 8601 date of last registration record change.'),
    expiry_date: z.string().optional().describe('ISO 8601 registration expiry date.'),
    rdap_last_updated: z
      .string()
      .optional()
      .describe('ISO 8601 timestamp of last RDAP database update.'),
    status: z
      .array(z.string())
      .describe('EPP status codes (e.g., clientTransferProhibited, serverDeleteProhibited).'),
    nameservers: z.array(z.string()).describe('Authoritative nameservers for this domain.'),
    dnssec_signed: z.boolean().describe('True when the domain has DNSSEC delegation signed.'),
    registrant_org: z
      .string()
      .optional()
      .describe('Registrant organization name. Omitted when privacy-redacted.'),
    registrant_redacted: z
      .boolean()
      .describe('True when registrant contact data is privacy-redacted (common post-GDPR).'),
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
      when: 'TLD has no RDAP server in the IANA bootstrap — cannot perform lookup.',
      recovery:
        'This TLD has no RDAP coverage. Use whois_check_availability to test registration status when possible.',
    },
    {
      reason: 'domain_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'RDAP server returned 404 — domain is not registered.',
      recovery:
        'The domain is not registered. Use whois_check_availability to confirm availability for registration.',
    },
  ],

  async handler(input, ctx) {
    if (!isValidFqdn(input.domain)) {
      throw ctx.fail('invalid_domain', `"${input.domain}" is not a valid FQDN.`, {
        ...ctx.recoveryFor('invalid_domain'),
      });
    }

    ctx.log.info('RDAP domain lookup', { domain: input.domain });

    const record = await getRdapService().lookupDomain(input.domain, ctx);

    if (!record.rdap_coverage) {
      throw ctx.fail('rdap_no_coverage', `No RDAP server found for the TLD of "${input.domain}".`, {
        domain: input.domain,
        ...ctx.recoveryFor('rdap_no_coverage'),
      });
    }

    return record;
  },

  format: (result) => {
    const lines: string[] = [];

    lines.push(`# Domain: ${result.domain}`);

    if (!result.rdap_coverage) {
      lines.push('**RDAP Coverage:** No — TLD has no RDAP server.');
      return [{ type: 'text', text: lines.join('\n') }];
    }

    lines.push(`**RDAP Coverage:** Yes`);
    if (result.registrar)
      lines.push(
        `**Registrar:** ${result.registrar}${result.registrar_iana_id ? ` (IANA #${result.registrar_iana_id})` : ''}`,
      );
    if (result.created_date) lines.push(`**Created:** ${result.created_date}`);
    if (result.expiry_date) lines.push(`**Expires:** ${result.expiry_date}`);
    if (result.updated_date) lines.push(`**Last Updated:** ${result.updated_date}`);
    if (result.rdap_last_updated) lines.push(`**RDAP DB Updated:** ${result.rdap_last_updated}`);
    if (result.handle) lines.push(`**Handle:** ${result.handle}`);
    lines.push(`**DNSSEC:** ${result.dnssec_signed ? 'Signed' : 'Not signed'}`);
    lines.push(
      `**Registrant Redacted:** ${result.registrant_redacted ? 'Yes (GDPR/privacy)' : 'No'}`,
    );
    if (result.registrant_org) lines.push(`**Registrant Org:** ${result.registrant_org}`);
    if (result.status.length > 0) lines.push(`**Status:** ${result.status.join(', ')}`);
    if (result.nameservers.length > 0)
      lines.push(`**Nameservers:** ${result.nameservers.join(', ')}`);

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
