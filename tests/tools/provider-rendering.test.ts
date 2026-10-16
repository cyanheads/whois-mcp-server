/**
 * @fileoverview Provider string fidelity through service, tool and Markdown rendering boundaries.
 * @module tests/tools/provider-rendering.test
 */
import { execFileSync } from 'node:child_process';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { literal } from '@/mcp-server/tools/definitions/_literal.js';
import { whoisGetDossier } from '@/mcp-server/tools/definitions/whois-get-dossier.tool.js';
import { whoisLookupAsn } from '@/mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupDomain } from '@/mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
});
const value = '  Example <Research> **Partners** [x](url) | \\ `\n```\n  last  ';
const escaped = value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
function html(markdown: string): string {
  return execFileSync('bun', ['-e', 'console.log(Bun.markdown.html(await Bun.stdin.text()))'], {
    input: markdown,
    encoding: 'utf8',
  });
}

describe('provider rendering characterization', () => {
  it('preserves strikethrough punctuation and adjacent fenced values', () => {
    expect(html(`**Registrar:** ${literal('~~Hidden Registrar~~')}`)).toContain(
      '<pre><code>~~Hidden Registrar~~\n</code></pre>',
    );
    const values = ['  first  ', 'second\tvalue', '~~third~~'];
    const rendered = html(`**Status:** ${values.map(literal).join(', ')}`);
    for (const value of values) expect(rendered).toContain(`<pre><code>${value}\n</code></pre>`);
  });
  it('renders every provider field path literally, including registrar detail', () => {
    const domainBase = {
      domain: 'example.com',
      rdap_coverage: true,
      status: [],
      nameservers: [],
      dnssec_signed: null,
      registrant_redacted: null,
    };
    const dossierBase = {
      domain: 'example.com',
      rdap_coverage: true,
      registered: true,
      age_days: null,
      dnssec_signed: null,
      privacy_redacted: null,
      status: [],
      nameservers: [],
      a_records: [],
      mx_records: [],
      ns_records: [],
      txt_records: [],
      dns_nxdomain: false,
      ns_provider: null,
      mx_provider: null,
    };
    const texts: string[] = [];
    for (const field of [
      'registrar',
      'registrar_iana_id',
      'created_date',
      'expiry_date',
      'updated_date',
      'rdap_last_updated',
      'handle',
      'registrant_org',
    ]) {
      texts.push(
        textOf({
          content: whoisLookupDomain.format!(
            whoisLookupDomain.output.parse({ ...domainBase, registrar: 'Plain', [field]: value }),
          ),
        }),
      );
    }
    for (const field of ['status', 'nameservers'])
      texts.push(
        textOf({
          content: whoisLookupDomain.format!(
            whoisLookupDomain.output.parse({ ...domainBase, [field]: [value] }),
          ),
        }),
      );
    for (const field of ['source', 'registrant_org', 'source_error'])
      texts.push(
        textOf({
          content: whoisLookupDomain.format!(
            whoisLookupDomain.output.parse({
              ...domainBase,
              registrar_detail: { status: 'found', [field]: value },
            }),
          ),
        }),
      );
    for (const field of [
      'registrar',
      'created_date',
      'expiry_date',
      'rdap_source_error',
      'dns_source_error',
      'ns_provider',
      'mx_provider',
    ])
      texts.push(
        textOf({
          content: whoisGetDossier.format!(
            whoisGetDossier.output.parse({ ...dossierBase, [field]: value }),
          ),
        }),
      );
    for (const field of ['status', 'nameservers', 'a_records', 'mx_records', 'ns_records'])
      texts.push(
        textOf({
          content: whoisGetDossier.format!(
            whoisGetDossier.output.parse({ ...dossierBase, [field]: [value] }),
          ),
        }),
      );
    for (const field of [
      'rdap_source',
      'org_name',
      'cidr',
      'start_address',
      'end_address',
      'name',
      'type',
      'ip_version',
      'country',
      'handle',
      'abuse_email',
      'ptr',
      'ptr_source_error',
    ])
      texts.push(
        textOf({
          content: whoisLookupIp.format!(
            whoisLookupIp.output.parse({
              ip: '8.8.8.8',
              cidrs: [],
              ptr: null,
              ptr_status: 'not_found',
              start_address: '8.8.8.0',
              end_address: '8.8.8.255',
              [field]: value,
            }),
          ),
        }),
      );
    texts.push(
      textOf({
        content: whoisLookupIp.format!(
          whoisLookupIp.output.parse({
            ip: '8.8.8.8',
            cidrs: [value],
            ptr: null,
            ptr_status: 'not_found',
          }),
        ),
      }),
    );
    for (const field of ['org_name', 'rir', 'name', 'type', 'country', 'handle'])
      texts.push(
        textOf({
          content: whoisLookupAsn.format!(
            whoisLookupAsn.output.parse({ asn: 'AS15169', [field]: value }),
          ),
        }),
      );
    const rendered: string[] = JSON.parse(
      execFileSync(
        'bun',
        [
          '-e',
          'console.log(JSON.stringify(JSON.parse(await Bun.stdin.text()).map(text => Bun.markdown.html(text))))',
        ],
        { input: JSON.stringify(texts), encoding: 'utf8' },
      ),
    );
    expect(rendered).toHaveLength(texts.length);
    for (const text of rendered) expect(text).toContain(`<pre><code>${escaped}\n</code></pre>`);
  });

  it('scans caller-sized punctuation and backtick runs linearly within a thread CPU bound', () => {
    const samples = [1250, 5000, 20000, 80000];
    const start = process.threadCpuUsage();
    const totals: number[] = [];
    for (const size of samples) {
      const text = `${'`'.repeat(size - 1)}<`;
      literal(text);
      const before = process.threadCpuUsage();
      for (let repeat = 0; repeat < 100; repeat++) {
        expect(literal(text).length).toBeGreaterThan(text.length);
        const used = process.threadCpuUsage(start);
        expect(used.user + used.system).toBeLessThan(1_000_000);
      }
      const elapsed = process.threadCpuUsage(before);
      totals.push(elapsed.user + elapsed.system);
    }
    expect(samples[3]! / samples[0]!).toBe(64);
    expect(totals[3]! / Math.max(1, totals[0]!)).toBeLessThan(256);
  });
  it('preserves provider values literally through all four real-service formatters (#31)', async () => {
    http = upstream({
      rdap: () =>
        Response.json({
          ldhName: 'example.com',
          handle: value,
          status: [value],
          name: value,
          type: value,
          country: value,
          events: [{ eventAction: 'expiration', eventDate: value }],
          entities: [
            {
              roles: ['registrar'],
              publicIds: [{ type: 'IANA Registrar ID', identifier: value }],
              vcardArray: ['vcard', [['fn', {}, 'text', value]]],
            },
            {
              entities: [
                {
                  roles: ['registrant'],
                  vcardArray: [
                    'vcard',
                    [
                      ['org', {}, 'text', value],
                      ['fn', {}, 'text', value],
                    ],
                  ],
                },
              ],
            },
          ],
        }),
    });
    const results = [
      await runToolContract(whoisLookupDomain, { domain: 'example.com' }),
      await runToolContract(whoisGetDossier, { domain: 'example.com' }),
      await runToolContract(whoisLookupIp, { ip: '8.8.8.8' }),
      await runToolContract(whoisLookupAsn, { asn: 'AS15169' }),
    ];
    for (const [index, result] of results.entries()) {
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject(
        index < 2 ? { registrar: value } : { name: value, org_name: value, handle: value },
      );
      const rendered = html(textOf(result));
      expect(rendered).toContain(`<pre><code>${escaped}\n</code></pre>`);
      expect(rendered).not.toContain('<Research>');
      expect(rendered).not.toContain('<strong>Partners</strong>');
    }
  });
  it('preserves plain provider names on both surfaces', async () => {
    http = upstream({
      rdap: () =>
        Response.json({
          ldhName: 'example.com',
          entities: [
            {
              roles: ['registrar'],
              vcardArray: ['vcard', [['fn', {}, 'text', 'Plain Registrar']]],
            },
          ],
        }),
    });
    const result = await runToolContract(whoisLookupDomain, { domain: 'example.com' });
    expect(result.structuredContent).toMatchObject({ registrar: 'Plain Registrar' });
    expect(textOf(result)).toContain('**Registrar:** Plain Registrar');
  });
});
