/**
 * @fileoverview whois_lookup_domain tool — domain registration lookup via RDAP with IANA bootstrap.
 * @module mcp-server/tools/definitions/whois-lookup-domain.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  getRdapService,
  icannRegistrableParent,
  isDomainNotFound,
} from '@/services/rdap/rdap-service.js';
import type { NormalizedDomain } from '@/services/rdap/types.js';
import { registrationNameInput, requireDomainName, unicodeDomainOutput } from './_fqdn.js';
import { literal } from './_literal.js';

export const whoisLookupDomain = tool('whois_lookup_domain', {
  title: 'Domain Registration Lookup',
  description:
    "Look up a domain's registration record — registrar, created/expiry dates, nameservers, EPP status codes, " +
    'provider DNSSEC evidence, and public registrant organization independently of contact redaction. Uses IANA bootstrap to select ' +
    'the correct per-TLD RDAP server, returning one normalized shape regardless of TLD. When the TLD has no RDAP ' +
    'coverage, throws rdap_no_coverage. A missing registry object throws domain_not_found; ' +
    'whois_check_availability returns record status without an eligibility guarantee. include_registrar opts into one ' +
    'bounded registrar referral with separate contact detail; registry fields remain authoritative.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    include_registrar: z
      .boolean()
      .default(false)
      .describe(
        'Follow one guarded registrar RDAP referral for optional contact detail. Registry fields remain authoritative; failed detail is disclosed without discarding the registry record.',
      ),
    domain: registrationNameInput,
  }),

  output: z.object({
    registrar_detail: z
      .object({
        status: z
          .enum(['found', 'no_referral', 'failed'])
          .describe('Optional registrar lookup outcome.'),
        source: z
          .string()
          .optional()
          .describe('Registrar RDAP source URL, or attempted referral on failure.'),
        registrant_org: z
          .string()
          .optional()
          .describe('Public registrar-reported organization, independent of contact redaction.'),
        registrant_redacted: z
          .boolean()
          .nullable()
          .optional()
          .describe('Explicit registrar privacy evidence; null when absent.'),
        source_error: z
          .string()
          .optional()
          .describe('Optional detail failure; registry fields remain usable.'),
      })
      .optional()
      .describe('Registrar contact detail only when include_registrar is true.'),
    domain: z.string().describe('Lowercase ASCII domain queried.'),
    unicode_domain: unicodeDomainOutput,
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
    dnssec_signed: z
      .boolean()
      .nullable()
      .describe('Provider delegationSigned value; null when absent.'),
    registrant_org: z
      .string()
      .optional()
      .describe(
        'Public registrant organization from jCard org. Omitted when absent or a placeholder; contact redaction is independent.',
      ),
    registrant_redacted: z
      .boolean()
      .nullable()
      .describe(
        'True for explicit registrant redaction evidence; null when privacy evidence is absent.',
      ),
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
      reason: 'rdap_no_coverage',
      code: JsonRpcErrorCode.NotFound,
      when: 'TLD has no RDAP server in the IANA bootstrap — cannot perform lookup.',
      recovery:
        'This TLD has no RDAP coverage. Use whois_get_dns for DNS evidence or whois_get_dossier for DNS with registration marked unknown. DNS answers cannot establish registration status.',
    },
    {
      reason: 'domain_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'RDAP server returned 404 — no domain record found.',
      recovery:
        'Use whois_check_availability for record status; a missing record does not establish registration eligibility.',
    },
  ],

  async handler(input, ctx) {
    const normalized = requireDomainName(input.domain, 'registration');
    const domain = normalized.domain.toLowerCase();
    ctx.log.info('RDAP domain lookup', { domain });

    let record: NormalizedDomain;
    try {
      record = await getRdapService().lookupDomain(normalized.domain, ctx, input.include_registrar);
    } catch (err) {
      // Re-throw domain_not_found with recovery hint from the typed contract
      if (isDomainNotFound(err)) {
        const parent = icannRegistrableParent(domain);
        throw ctx.fail('domain_not_found', err.message, {
          domain,
          ...(parent
            ? {
                registrable_parent: parent,
                recovery: {
                  hint: `Query "${parent}" with whois_lookup_domain to check its registration record.`,
                },
              }
            : ctx.recoveryFor('domain_not_found')),
        });
      }
      throw err;
    }

    if (!record.rdap_coverage) {
      throw ctx.fail(
        'rdap_no_coverage',
        `No RDAP server found for the TLD of "${normalized.domain}".`,
        { domain: normalized.domain },
      );
    }

    return { ...record, ...normalized, domain };
  },

  format: (result) => {
    const lines: string[] = [];

    lines.push(`# Domain: ${literal(result.domain)}`);
    if (result.unicode_domain) lines.push(`**Unicode Display:** ${literal(result.unicode_domain)}`);

    if (!result.rdap_coverage) {
      lines.push('**RDAP Coverage:** No — TLD has no RDAP server.');
      return [{ type: 'text', text: lines.join('\n') }];
    }

    lines.push(`**RDAP Coverage:** Yes`);
    if (result.registrar)
      lines.push(
        `**Registrar:** ${literal(result.registrar)}${result.registrar_iana_id ? ` (IANA #${literal(result.registrar_iana_id)})` : ''}`,
      );
    if (result.created_date) lines.push(`**Created:** ${literal(result.created_date)}`);
    if (result.expiry_date) lines.push(`**Expires:** ${literal(result.expiry_date)}`);
    if (result.updated_date) lines.push(`**Last Updated:** ${literal(result.updated_date)}`);
    if (result.rdap_last_updated)
      lines.push(`**RDAP DB Updated:** ${literal(result.rdap_last_updated)}`);
    if (result.handle) lines.push(`**Handle:** ${literal(result.handle)}`);
    lines.push(
      `**DNSSEC:** ${result.dnssec_signed === null ? 'Unknown' : result.dnssec_signed ? 'Signed' : 'Not signed'}`,
    );
    lines.push(
      `**Registrant Redacted:** ${result.registrant_redacted === null ? 'Unknown' : result.registrant_redacted ? 'Yes (GDPR/privacy)' : 'No'}`,
    );
    if (result.registrant_org) lines.push(`**Registrant Org:** ${literal(result.registrant_org)}`);
    if (result.status.length > 0)
      lines.push(`**Status:** ${result.status.map(literal).join(', ')}`);
    if (result.nameservers.length > 0)
      lines.push(`**Nameservers:** ${result.nameservers.map(literal).join(', ')}`);
    if (result.registrar_detail) {
      const detail = result.registrar_detail;
      lines.push(`**Registrar Detail:** ${detail.status}`);
      if (detail.source) lines.push(`**Registrar Source:** ${literal(detail.source)}`);
      if (detail.registrant_org)
        lines.push(`**Registrar Registrant Org:** ${literal(detail.registrant_org)}`);
      if (detail.status === 'found')
        lines.push(
          `**Registrar Registrant Redacted:** ${detail.registrant_redacted === null ? 'Unknown' : detail.registrant_redacted ? 'Yes' : 'No'}`,
        );
      if (detail.source_error)
        lines.push(`**Registrar Detail Error:** ${literal(detail.source_error)}`);
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
