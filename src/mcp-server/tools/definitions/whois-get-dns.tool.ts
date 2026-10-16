/**
 * @fileoverview whois_get_dns tool — multi-type DNS record lookup via DNS-over-HTTPS.
 * @module mcp-server/tools/definitions/whois-get-dns.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getDohService } from '@/services/doh/doh-service.js';
import { DNS_NAME_PATTERN } from './_fqdn.js';

const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'PTR'] as const;

export const whoisGetDns = tool('whois_get_dns', {
  title: 'DNS Record Lookup',
  description:
    'Fetch DNS records for a domain via DNS-over-HTTPS. Supports A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR. ' +
    'Multiple types are fetched in parallel. NXDOMAIN is returned as nxdomain: true in the result, not as an ' +
    'error — the terminal name does not exist; preceding alias answers are retained. NOERROR with no answers is empty data; DNS failure codes ' +
    'and truncated responses are errors after retries and fallback. TXT values are returned completely and rendered literally.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    domain: z
      .string()
      .max(254)
      .regex(
        DNS_NAME_PATTERN,
        'Provide an ASCII DNS owner such as _dmarc.example.com; labels are 1–63 characters and one terminal root dot is allowed.',
      )
      .describe(
        'ASCII DNS owner name, including underscore labels (e.g., "_dmarc.github.com"). One terminal root dot is normalized; labels are 1–63 characters and the normalized name is at most 253.',
      ),
    types: z
      .array(z.enum(DNS_RECORD_TYPES).describe('A DNS record type to fetch.'))
      .min(1)
      .default(['A', 'AAAA', 'MX', 'TXT', 'NS'])
      .describe(
        'Nonempty list of DNS record types to fetch; duplicates are queried once. Defaults to [A, AAAA, MX, TXT, NS]. ' +
          'Specify more types to expand coverage (e.g., add CAA to check certificate authority authorization).',
      ),
  }),

  output: z.object({
    domain: z.string().describe('Domain queried.'),
    nxdomain: z
      .boolean()
      .describe(
        'True when at least one requested type returned NXDOMAIN / Status 3. ' +
          'Supported answers, including aliases preceding the absent terminal name, remain in records. This is data, not an error.',
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
        'Aggregate resolver indicator: cloudflare when any query consumed a successful Cloudflare response; ' +
          'otherwise nextdns. See query_sources for each requested type.',
      ),
    query_sources: z
      .array(
        z
          .object({
            type: z
              .enum(DNS_RECORD_TYPES)
              .describe('Requested DNS record type, which may differ from an answer type.'),
            source: z
              .enum(['cloudflare', 'nextdns'])
              .describe(
                'Resolver whose successful response was consumed, including empty answers and NXDOMAIN.',
              ),
          })
          .describe('Resolver attribution for one requested type.'),
      )
      .describe('One entry per unique requested type, in first-requested order.'),
  }),

  errors: [
    {
      reason: 'dns_response_failed',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'Resolvers return a DNS failure status or truncated response after retry and fallback.',
      recovery: 'Retry the DNS query later or choose another record type.',
      thrownBy: 'service',
      retryable: true,
    },
  ],

  async handler(input, ctx) {
    ctx.log.info('DNS lookup via DoH', { domain: input.domain, types: input.types });
    return await getDohService().lookup(input.domain.replace(/\.$/, ''), input.types, ctx);
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# DNS Records: ${result.domain}`);
    lines.push(
      `**Source (aggregate):** ${result.source} — ${result.source === 'cloudflare' ? 'at least one query used Cloudflare' : 'all queries used NextDNS'}`,
    );
    lines.push(
      `**Query sources:** ${result.query_sources.map((query) => `${query.type}: ${query.source}`).join(', ')}`,
    );
    lines.push(
      `**NXDOMAIN:** ${result.nxdomain === true ? 'Yes — at least one query returned NXDOMAIN' : 'No'}`,
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
        // Backticks distinguish TXT data visually; they are not a security boundary.
        if (type === 'TXT') {
          let longestRun = 0;
          for (const run of rec.data.matchAll(/`+/g))
            longestRun = Math.max(longestRun, run[0].length);
          const fence = '`'.repeat(Math.max(3, longestRun + 1));
          lines.push(`- name: ${rec.name} | TTL: ${rec.ttl}s`, `${fence}\n${rec.data}\n${fence}`);
        } else lines.push(`- **${rec.data}** | name: ${rec.name} | TTL: ${rec.ttl}s`);
      }
    }

    if (result.records.length === 0 && result.nxdomain !== true) {
      lines.push('\nNo records found for the requested types.');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
