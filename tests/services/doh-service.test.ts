/**
 * @fileoverview Real DoH routing, fallback, and query provenance contracts.
 * @module tests/services/doh-service.test
 */

import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisGetDns } from '@/mcp-server/tools/definitions/whois-get-dns.tool.js';
import { DohService } from '@/services/doh/doh-service.js';
import type { DnsRecordType } from '@/services/doh/types.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('DoH characterization', () => {
  it('uses Cloudflare primary and NextDNS-only CAA with the legacy aggregate', async () => {
    http = upstream();
    const result = await new DohService().lookup('example.com', ['A', 'CAA'], createMockContext());
    expect(result).toMatchObject({ records: [], nxdomain: false, source: 'cloudflare' });
    expect(http.calls.map((call) => new URL(call.request.url).hostname)).toEqual([
      'cloudflare-dns.com',
      'dns.nextdns.io',
    ]);
  });

  it('falls back to NextDNS after a failed Cloudflare attempt', async () => {
    http = upstream({
      dns: (_type, url) =>
        url.hostname === 'cloudflare-dns.com'
          ? new Response(null, { status: 400 })
          : Response.json({ Status: 0 }),
    });
    const result = await new DohService().lookup('example.com', ['A'], createMockContext());
    expect(result.source).toBe('nextdns');
    expect(http.calls.map((call) => new URL(call.request.url).hostname)).toEqual([
      'cloudflare-dns.com',
      'dns.nextdns.io',
    ]);
  });

  it.each([0, 3])('preserves DNS status %s as data', async (Status) => {
    http = upstream({ dns: () => Response.json({ Status }) });
    const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: ['A'] });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      records: [],
      source: 'cloudflare',
      nxdomain: Status === 3,
    });
    expect(textOf(result)).toContain('cloudflare');
    expect(textOf(result)).toContain(Status === 3 ? 'does not exist' : 'No records');
  });

  it('omitting types dispatches exactly the five defaults', async () => {
    http = upstream();
    const result = await runToolContract(whoisGetDns, { domain: 'example.com' });
    expect(result.isError).not.toBe(true);
    expect(http.calls.map((call) => new URL(call.request.url).searchParams.get('type'))).toEqual([
      'A',
      'AAAA',
      'MX',
      'TXT',
      'NS',
    ]);
  });
});

describe('DNS regression #9 and #10', () => {
  it('rejects explicit empty types at the public boundary before fetch (#9)', async () => {
    http = upstream();
    expect(whoisGetDns.input.safeParse({ domain: 'example.com', types: [] }).success).toBe(false);
    const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: [] });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: { code: -32602, data: { reason: 'invalid_arguments' } },
    });
    expect(result.structuredContent).not.toHaveProperty('source');
    expect(textOf(result)).toContain('types');
    expect(textOf(result)).toContain('1');
    expect(textOf(result)).not.toContain('**Source');
    expect(textOf(result)).not.toContain('nextdns');
    expect(textOf(result)).not.toContain('cloudflare');
    expect(http.calls).toHaveLength(0);
  });

  it.each(['primary', 'mixed', 'partial-fallback', 'all-fallback'] as const)(
    'attributes %s responses in dispatch order with deduplication (#10)',
    async (mode) => {
      http = upstream({
        dns: async (type, url) => {
          if (
            url.hostname === 'cloudflare-dns.com' &&
            (mode === 'all-fallback' || (mode === 'partial-fallback' && type === 'MX'))
          )
            return new Response(null, { status: 400 });
          if (type === 'A') await new Promise((resolve) => setTimeout(resolve, 15));
          return Response.json({
            Status: 0,
            Answer: [
              {
                type: type === 'A' ? 5 : 15,
                name: 'example.com',
                TTL: 60,
                data: `${type}.example.com`,
              },
            ],
          });
        },
      });
      const types: DnsRecordType[] = mode === 'mixed' ? ['A', 'CAA', 'A'] : ['A', 'MX', 'A'];
      const result = await runToolContract(whoisGetDns, { domain: 'example.com', types });
      const querySources = [
        { type: 'A', source: mode === 'all-fallback' ? 'nextdns' : 'cloudflare' },
        { type: types[1], source: mode === 'primary' ? 'cloudflare' : 'nextdns' },
      ];
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        source: mode === 'all-fallback' ? 'nextdns' : 'cloudflare',
        query_sources: querySources,
      });
      for (const query of querySources)
        expect(textOf(result)).toContain(`${query.type}: ${query.source}`);
      expect(http.calls).toHaveLength(
        mode === 'all-fallback' ? 4 : mode === 'partial-fallback' ? 3 : 2,
      );
    },
  );

  it.each([0, 3])('attributes empty status %s for every requested type (#10)', async (Status) => {
    http = upstream({ dns: () => Response.json({ Status }) });
    const result = await runToolContract(whoisGetDns, {
      domain: 'example.com',
      types: ['CAA', 'A'],
    });
    expect(result.structuredContent).toMatchObject({
      records: [],
      nxdomain: Status === 3,
      query_sources: [
        { type: 'CAA', source: 'nextdns' },
        { type: 'A', source: 'cloudflare' },
      ],
    });
    expect(textOf(result)).toContain('CAA: nextdns');
    expect(textOf(result)).toContain('A: cloudflare');
  });
});

describe('DoH retry and terminal paths', () => {
  it('exhausts primary retries, then consumes the third fallback attempt', async () => {
    vi.useFakeTimers();
    let fallbackAttempts = 0;
    http = upstream({
      dns: (_type, url) => {
        if (url.hostname === 'cloudflare-dns.com' || ++fallbackAttempts < 3)
          return new Response(null, { status: 503 });
        return Response.json({ Status: 0 });
      },
    });
    const resultPromise = runToolContract(whoisGetDns, { domain: 'example.com', types: ['MX'] });
    await vi.runAllTimersAsync();
    const result = await resultPromise;
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      source: 'nextdns',
      records: [],
      query_sources: [{ type: 'MX', source: 'nextdns' }],
    });
    expect(textOf(result)).toContain('MX: nextdns');
    expect(http.calls.map((call) => new URL(call.request.url).hostname)).toEqual([
      'cloudflare-dns.com',
      'cloudflare-dns.com',
      'cloudflare-dns.com',
      'dns.nextdns.io',
      'dns.nextdns.io',
      'dns.nextdns.io',
    ]);
  });
  it('consumes a successful primary retry without falling back', async () => {
    vi.useFakeTimers();
    let attempts = 0;
    http = upstream({
      dns: () =>
        ++attempts < 3 ? new Response(null, { status: 503 }) : Response.json({ Status: 0 }),
    });
    const pending = runToolContract(whoisGetDns, { domain: 'example.com', types: ['A'] });
    await vi.runAllTimersAsync();
    expect((await pending).structuredContent).toMatchObject({
      query_sources: [{ type: 'A', source: 'cloudflare' }],
    });
    expect(http.calls).toHaveLength(3);
  });
  it.each(['A', 'CAA'] as const)(
    'preserves terminal failure for %s without fabricated sources',
    async (type) => {
      http = upstream({ dns: () => new Response(null, { status: 400 }) });
      const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: [type] });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).not.toHaveProperty('source');
      expect(result.structuredContent).not.toHaveProperty('query_sources');
      expect(http.calls).toHaveLength(2);
      if (type === 'CAA')
        expect(
          http.calls.every((call) => new URL(call.request.url).hostname === 'dns.nextdns.io'),
        ).toBe(true);
    },
  );
});
