/**
 * @fileoverview whois_get_dns tool — multi-type DNS record lookup via DNS-over-HTTPS.
 * @module mcp-server/tools/definitions/whois-get-dns.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getDohService } from '@/services/doh/doh-service.js';
import type { DnsRecordType } from '@/services/doh/types.js';
import { isValidFqdn } from './_fqdn.js';

const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'PTR'] as const;

export const whoisGetDns = tool('whois_get_dns', {
  title: 'DNS Record Lookup',
  description:
    'Fetch DNS records for a domain via DNS-over-HTTPS. Supports A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR. ' +
    'Multiple types are fetched in parallel. NXDOMAIN is returned as nxdomain: true in the result, not as an ' +
    'error — it means the domain does not exist in DNS.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    domain: z
      .string()
      .describe(
        'Fully qualified domain name or hostname to query (e.g., "github.com", "mail.example.com").',
      ),
    types: z
      .array(z.enum(DNS_RECORD_TYPES).describe('A DNS record type to fetch.'))
      .default(['A', 'AAAA', 'MX', 'TXT', 'NS'])
      .describe(
        'DNS record types to fetch. Defaults to [A, AAAA, MX, TXT, NS]. ' +
          'Specify more types to expand coverage (e.g., add CAA to check certificate authority authorization).',
      ),
  }),

  output: z.object({
    domain: z.string().describe('Domain queried.'),
    nxdomain: z
      .boolean()
      .describe(
        'True when the domain does not exist in DNS (NXDOMAIN / Status 3). ' +
          'Records will be empty. This is a valid data signal, not an error.',
      ),
    records: z
      .array(
        z
          .object({
            type: z.enum(DNS_RECORD_TYPES).describe('DNS record type.'),
            name: z.string().describe('Record owner name.'),
            ttl: z.number().describe('Time-to-live in seconds.'),
            data: z.string().describe('Record data (IP address, hostname, text, etc.).'),
          })
          .describe('A single DNS resource record.'),
      )
      .describe('DNS records returned for the requested types.'),
    source: z
      .enum(['cloudflare', 'nextdns'])
      .describe(
        'The DoH resolver that provided results (cloudflare = primary used for most types, nextdns = fallback or CAA).',
      ),
  }),

  errors: [
    {
      reason: 'invalid_domain',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Input is not a valid FQDN.',
      recovery:
        'Provide a valid fully-qualified domain name like "example.com" or "sub.example.org".',
    },
  ],

  async handler(input, ctx) {
    if (!isValidFqdn(input.domain)) {
      throw ctx.fail('invalid_domain', `"${input.domain}" is not a valid FQDN.`, {
        ...ctx.recoveryFor('invalid_domain'),
      });
    }

    ctx.log.info('DNS lookup via DoH', { domain: input.domain, types: input.types });

    const result = await getDohService().lookup(input.domain, input.types as DnsRecordType[], ctx);

    return {
      domain: result.domain,
      nxdomain: result.nxdomain,
      records: result.records,
      source: result.source,
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# DNS Records: ${result.domain}`);
    lines.push(`**Source:** ${result.source}`);
    lines.push(
      `**NXDOMAIN:** ${result.nxdomain === true ? 'Yes — domain does not exist in DNS' : 'No'}`,
    );

    // Group records by type and render all fields (name, ttl, data)
    const byType = new Map<string, typeof result.records>();
    for (const rec of result.records) {
      const list = byType.get(rec.type) ?? [];
      list.push(rec);
      byType.set(rec.type, list);
    }

    for (const [type, recs] of byType) {
      lines.push(`\n## ${type}`);
      for (const rec of recs) {
        // TXT records are attacker-controlled free-text and must be fenced to prevent prompt injection
        const data = type === 'TXT' ? `\`${rec.data}\`` : rec.data;
        lines.push(`- **${data}** | name: ${rec.name} | TTL: ${rec.ttl}s`);
      }
    }

    if (result.records.length === 0 && result.nxdomain !== true) {
      lines.push('\nNo records found for the requested types.');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
