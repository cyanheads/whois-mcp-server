/**
 * @fileoverview Dossier TXT and provider labels through actual RDAP/DoH services.
 * @module tests/tools/dossier-contracts.test
 */

import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisGetDossier } from '@/mcp-server/tools/definitions/whois-get-dossier.tool.js';
import { DNS_TYPE_NUMBERS, type DnsRecordType } from '@/services/doh/types.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
});

function dossier(records: Partial<Record<DnsRecordType, string[]>>) {
  http = upstream({
    dns: (type) =>
      Response.json({
        Status: 0,
        Answer: (records[type] ?? []).map((data) => ({
          type: DNS_TYPE_NUMBERS[type],
          name: 'example.com',
          TTL: 60,
          data,
        })),
      }),
  });
  return runToolContract(whoisGetDossier, { domain: 'example.com' });
}

describe('dossier characterization', () => {
  it.each([0, 1, 3])('preserves %s ordinary TXT values', async (count) => {
    const values = ['first', 'second', 'third'].slice(0, count);
    const result = await dossier({ TXT: values });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      txt_records: values,
      registered: true,
      rdap_coverage: true,
    });
    for (const value of values) expect(textOf(result)).toContain(value);
    if (count === 0) {
      expect(textOf(result)).not.toContain('**TXT:**');
      expect(textOf(result)).not.toMatch(/^`{3,}/m);
    }
  });

  it('infers from the first record and preserves ordinary unknown fallback', async () => {
    const result = await dossier({
      NS: ['NS1.CLOUDFLARE.COM.', 'ns.google.com.'],
      MX: ['10 mail.example.net.', '1 aspmx.l.google.com.'],
    });
    expect(result.structuredContent).toMatchObject({
      ns_provider: 'Cloudflare',
      mx_provider: 'example',
      ns_records: ['NS1.CLOUDFLARE.COM', 'ns.google.com'],
      mx_records: ['10 mail.example.net', '1 aspmx.l.google.com'],
    });
    expect(textOf(result)).toContain('Cloudflare');
    expect(textOf(result)).toContain('**Mail Provider:** example');
  });
});

describe('TXT regression #8', () => {
  it.each([1, 3, 5, 8])(
    'preserves all %s literal values, including duplicates and fence-like data',
    async (count) => {
      const values = [
        '"quoted"',
        'back`tick | pipe',
        'back`tick | pipe',
        'fourth\\\\value',
        'line one\n```\nline two',
        '``````',
        '',
        'last\n',
      ].slice(0, count);
      const result = await dossier({ TXT: values });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ txt_records: values });
      const text = textOf(result);
      const rendered = Array.from(
        text.matchAll(/^(`{3,})\n([\s\S]*?)\n\1$/gm),
        (match) => match[2],
      );
      expect(rendered).toEqual(values);
    },
  );
});

const nsProviders = [
  ['ns.cloudflare.com', 'Cloudflare'],
  ['ns.awsdns-12.com', 'AWS Route 53'],
  ['ns.awsdns-12.net', 'AWS Route 53'],
  ['ns.awsdns-12.org', 'AWS Route 53'],
  ['ns.awsdns-12.co.uk', 'AWS Route 53'],
  ['ns.amazonaws.com', 'AWS Route 53'],
  ['ns.google.com', 'Google Cloud DNS'],
  ['ns.googledomains.com', 'Google Cloud DNS'],
  ['ns.azure-dns.com', 'Azure DNS'],
  ['ns.azure-dns.net', 'Azure DNS'],
  ['ns.azure-dns.org', 'Azure DNS'],
  ['ns.azure-dns.info', 'Azure DNS'],
  ['ns.microsoftdns.com', 'Azure DNS'],
  ['ns.namebrightdns.com', 'NameBright'],
  ['ns.namebright.com', 'NameBright'],
  ['dns.nsone.net', 'NS1'],
  ['dns.ns1.com', 'NS1'],
  ['ns.dnsimple.com', 'DNSimple'],
  ['ns.domaincontrol.com', 'GoDaddy'],
  ['ns.name.com', 'Name.com'],
  ['ns.registrar-servers.com', 'Namecheap'],
] as const;
const mxProviders = [
  ['aspmx.l.google.com', 'Google Workspace'],
  ['mx.googlemail.com', 'Google Workspace'],
  ['tenant.mail.protection.outlook.com', 'Microsoft 365'],
  ['mx.microsoft.com', 'Microsoft 365'],
  ['mx.office365.com', 'Microsoft 365'],
  ['mx.mxroute.com', 'MXroute'],
  ['mx.mailchannels.net', 'MailChannels'],
  ['mx.amazonses.com', 'Amazon SES'],
  ['mx.amazonaws.com', 'Amazon SES'],
  ['mx.fastmail.com', 'Fastmail'],
  ['in1-smtp.messagingengine.com', 'Fastmail'],
  ['mail.protonmail.ch', 'ProtonMail'],
  ['mx.protonmail.com', 'ProtonMail'],
  ['mx.zoho.com', 'Zoho Mail'],
  ['mx.sendgrid.net', 'SendGrid'],
  ['mx.mailgun.org', 'Mailgun'],
] as const;

describe('DNS provider regression #12', () => {
  it.each(nsProviders)('recognizes NS %s only on domain boundaries', async (host, provider) => {
    const result = await dossier({ NS: [`${host.toUpperCase()}.`] });
    expect(result.structuredContent).toMatchObject({
      ns_provider: provider,
      ns_records: [host.toUpperCase()],
    });
    expect(textOf(result)).toContain(`**NS Provider:** ${provider}`);
    http.restore();
    vi.restoreAllMocks();
    const lookalike = await dossier({ NS: [`${host}.evil.example.`] });
    expect(lookalike.structuredContent).toMatchObject({ ns_provider: 'evil' });
  });
  it.each(mxProviders)('recognizes MX %s only on domain boundaries', async (host, provider) => {
    const result = await dossier({ MX: [`10 ${host.toUpperCase()}.`] });
    expect(result.structuredContent).toMatchObject({
      mx_provider: provider,
      mx_records: [`10 ${host.toUpperCase()}`],
    });
    expect(textOf(result)).toContain(`**Mail Provider:** ${provider}`);
    http.restore();
    vi.restoreAllMocks();
    const lookalike = await dossier({ MX: [`10 ${host}.evil.example.`] });
    expect(lookalike.structuredContent).toMatchObject({ mx_provider: 'evil' });
  });
  it.each([
    ['ns1.hostname.com', 'hostname'],
    ['ns1.company-dns.net', 'company-dns'],
    ['cloudflare.evil.example', 'evil'],
    ['awsdns-12.com.evil.example', 'evil'],
  ])('does not label NS keyword lookalike %s', async (host, fallback) => {
    expect((await dossier({ NS: [host] })).structuredContent).toMatchObject({
      ns_provider: fallback,
    });
  });
  it.each([
    ['10 example.com.', 'example'],
    ['0 .', null],
    ['10 aspmx.evil.example.', 'evil'],
  ])('normalizes MX %s before fallback', async (mx, provider) => {
    expect((await dossier({ MX: [mx] })).structuredContent).toMatchObject({
      mx_provider: provider,
    });
  });
});
