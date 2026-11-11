/**
 * @fileoverview Dossier TXT and provider labels through actual RDAP/DoH services.
 * @module tests/tools/dossier-contracts.test
 */

import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
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
  it('keeps an exact third-level .name registration', async () => {
    http = upstream({
      dnsSuffixes: ['name'],
      rdap: () => Response.json({ ldhName: 'joe.example.name' }),
    });
    const result = await runToolContract(whoisGetDossier, { domain: 'joe.example.name' });
    expect(result.structuredContent).toMatchObject({
      domain: 'joe.example.name',
      registered: true,
    });
    expect(result.structuredContent).not.toHaveProperty('registration_domain');
    expect(rdapPaths()).toEqual(['/domain/joe.example.name']);
    expect(textOf(result)).toContain('**Registered (RDAP record):** Found');
  });
  it('preserves null MX and labels its explicit no-mail meaning (#28)', async () => {
    const result = await dossier({ MX: ['0 .'] });
    expect(result.structuredContent).toMatchObject({ mx_records: ['0 .'], mx_provider: null });
    expect(textOf(result)).toContain('**MX:** 0 .');
    expect(textOf(result)).toContain('accepts no mail');
  });
  it('keeps ordinary and absent MX evidence distinct', async () => {
    const result = await dossier({ MX: ['10 mail.example.net.'] });
    expect(result.structuredContent).toMatchObject({ mx_records: ['10 mail.example.net'] });
    http.restore();
    vi.restoreAllMocks();
    const empty = await dossier({});
    expect(empty.structuredContent).toMatchObject({ mx_records: [], mx_provider: null });
    expect(textOf(empty)).not.toContain('accepts no mail');
  });
  it.each([
    [200, true, true, 'Found'],
    [404, true, false, 'Not found'],
    [200, false, null, 'Unknown'],
  ] as const)(
    'renders registry record status for HTTP %s and coverage %s (#18)',
    async (status, coverage, registered, label) => {
      http = upstream({
        coverage,
        rdap: () =>
          status === 404
            ? new Response(null, { status: 404 })
            : Response.json({ ldhName: 'example.com' }),
      });
      const result = await runToolContract(whoisGetDossier, { domain: 'example.com' });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ registered, rdap_coverage: coverage });
      expect(
        textOf(result)
          .split('\n')
          .filter((line) => line.startsWith('**Registered (RDAP record):**')),
      ).toEqual([`**Registered (RDAP record):** ${label}`]);
      expect(textOf(result)).not.toContain('**Registered:**');
    },
  );
  it('keeps absent RDAP coverage evidence unknown on both surfaces (#20)', async () => {
    http = upstream({ coverage: false });
    const result = await runToolContract(whoisGetDossier, { domain: 'example.invalid' });
    expect(result.structuredContent).toMatchObject({
      rdap_coverage: false,
      dnssec_signed: null,
      privacy_redacted: null,
    });
    expect(textOf(result)).toContain('DNSSEC:** Unknown');
    expect(textOf(result)).toContain('Privacy Redacted:** Unknown');
  });
  it('retains registry data when DNS failure status exhausts fallback (#16)', async () => {
    vi.useFakeTimers();
    http = upstream({ dns: () => Response.json({ Status: 2 }) });
    const pending = runToolContract(whoisGetDossier, { domain: 'example.com' });
    await vi.runAllTimersAsync();
    const result = await pending;
    expect(result.structuredContent).toMatchObject({
      registered: true,
      dns_nxdomain: null,
      dns_source_error: expect.stringContaining('RCODE 2'),
    });
    expect(textOf(result)).toContain('DNS:** Failed');
    vi.useRealTimers();
  });
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

function rdapPaths() {
  return http.calls
    .map(({ request }) => new URL(request.url).pathname)
    .filter((path) => path.startsWith('/domain/'));
}

describe('dossier registration subject (#35)', () => {
  it.each([true, false])(
    'preserves exact registration evidence after the fallback budget (found: %s)',
    async (found) => {
      const timeout = AbortSignal.timeout.bind(AbortSignal);
      vi.spyOn(AbortSignal, 'timeout').mockImplementation((durationMs) =>
        durationMs === 45_000
          ? AbortSignal.abort(new DOMException('Fallback budget expired', 'TimeoutError'))
          : timeout(durationMs),
      );
      http = upstream({
        rdap: () =>
          found
            ? Response.json({ ldhName: 'www.example.com' })
            : new Response(null, { status: 404 }),
      });
      const result = await runToolContract(whoisGetDossier, { domain: 'www.example.com' });
      expect(result.structuredContent).toMatchObject({ registered: found, rdap_coverage: true });
      expect(result.structuredContent).not.toHaveProperty('registration_domain');
      expect(result.structuredContent).not.toHaveProperty('rdap_source_error');
      expect(rdapPaths()).toEqual(['/domain/www.example.com']);
      expect(textOf(result)).toContain(found ? 'record):** Found' : 'record):** Not found');
    },
  );

  it.each([
    ['www.example.com', 'example.com', true],
    ['nested.example.github.io', 'github.io', false],
  ] as const)('separates DNS on %s from RDAP on %s', async (domain, parent, registered) => {
    http = upstream({
      dnsSuffixes: ['com', 'io'],
      dns: (_type, url) => {
        expect(url.searchParams.get('name')).toBe(domain);
        return Response.json({ Status: 0 });
      },
      rdap: (url) =>
        registered && url.pathname === `/domain/${parent}`
          ? Response.json({ ldhName: parent })
          : new Response(null, { status: 404 }),
    });
    const result = await runToolContract(whoisGetDossier, { domain });
    expect(result.structuredContent).toMatchObject({
      domain,
      registration_domain: parent,
      registered,
      rdap_coverage: true,
      dns_nxdomain: false,
    });
    expect(rdapPaths()).toEqual([`/domain/${domain}`, `/domain/${parent}`]);
    expect(textOf(result)).toContain(`**Registration Domain:** ${parent}`);
    expect(textOf(result)).toContain(registered ? 'record):** Found' : 'record):** Not found');
  });

  it('does not infer a parent for an unknown suffix', async () => {
    http = upstream({ dnsSuffixes: ['invalid'], rdap: () => new Response(null, { status: 404 }) });
    const result = await runToolContract(whoisGetDossier, { domain: 'www.example.invalid' });
    expect(result.structuredContent).toMatchObject({ registered: false, rdap_coverage: true });
    expect(result.structuredContent).not.toHaveProperty('registration_domain');
    expect(rdapPaths()).toEqual(['/domain/www.example.invalid']);
  });

  it('makes no parent request when the exact name has no coverage', async () => {
    http = upstream({ coverage: false });
    const result = await runToolContract(whoisGetDossier, { domain: 'www.example.com' });
    expect(result.structuredContent).toMatchObject({ registered: null, rdap_coverage: false });
    expect(result.structuredContent).not.toHaveProperty('registration_domain');
    expect(rdapPaths()).toEqual([]);
  });

  it.each([false, true])(
    'retains DNS on registry failure (parent attempted: %s)',
    async (parent) => {
      http = upstream({
        rdap: (url) =>
          parent && url.pathname === '/domain/www.example.com'
            ? new Response(null, { status: 404 })
            : Response.json({ ldhName: 'wrong.com' }),
      });
      const result = await runToolContract(whoisGetDossier, { domain: 'www.example.com' });
      expect(result.structuredContent).toMatchObject({
        registered: null,
        rdap_coverage: null,
        rdap_source_error: expect.stringContaining('matching domain'),
        dns_nxdomain: false,
        ...(parent ? { registration_domain: 'example.com' } : {}),
      });
      if (!parent) expect(result.structuredContent).not.toHaveProperty('registration_domain');
      expect(rdapPaths()).toEqual(
        parent ? ['/domain/www.example.com', '/domain/example.com'] : ['/domain/www.example.com'],
      );
      expect(textOf(result)).toContain('**RDAP:** Failed');
    },
  );

  it.each([false, true])(
    'propagates caller cancellation (parent attempted: %s)',
    async (parent) => {
      const controller = new AbortController();
      const reason = new DOMException('Fixture cancellation', 'AbortError');
      http = upstream({
        rdap: (url) => {
          if (!parent || url.pathname === '/domain/example.com') controller.abort(reason);
          return new Response(null, { status: 404 });
        },
      });
      const ctx = createMockContext({ signal: controller.signal, errors: whoisGetDossier.errors });
      await expect(whoisGetDossier.handler({ domain: 'www.example.com' }, ctx)).rejects.toBe(
        reason,
      );
      expect(rdapPaths()).toEqual(
        parent ? ['/domain/www.example.com', '/domain/example.com'] : ['/domain/www.example.com'],
      );
    },
  );
});

describe('ICANN provider label fallback (#36)', () => {
  it.each([
    ['DNS0.BBC.CO.UK.', '10 MAIL.OTHER.CO.UK.', 'bbc', 'other'],
    ['co.uk.', '10 co.uk.', null, null],
    ['ns.foo.github.io.', '10 mx.bar.github.io.', 'github', 'github'],
  ] as const)(
    'infers from %s and %s without changing the records',
    async (ns, mx, nsLabel, mxLabel) => {
      const result = await dossier({ NS: [ns], MX: [mx] });
      expect(result.structuredContent).toMatchObject({
        ns_provider: nsLabel,
        mx_provider: mxLabel,
        ns_records: [ns.slice(0, -1)],
        mx_records: [mx.slice(0, -1)],
      });
      expect(textOf(result)).toContain(`**NS Provider:** ${nsLabel ?? 'Unknown'}`);
      expect(textOf(result)).toContain(`**Mail Provider:** ${mxLabel ?? 'None / Unknown'}`);
    },
  );
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
