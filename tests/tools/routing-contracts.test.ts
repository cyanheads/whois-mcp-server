/**
 * @fileoverview Optional routing lookup contracts through real services and the HTTP boundary.
 * @module tests/tools/routing-contracts.test
 */
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupAsn } from '@/mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('optional routing characterization', () => {
  it.each([
    ['8.8.8.8', '1.1.1.0/24', 'failed'],
    ['8.8.8.8', '2001:4860::/32', 'failed'],
    ['2001:4860:4860::8888', '8.8.8.0/24', 'failed'],
    ['8.8.8.8', '0.0.0.0/0', 'found'],
    ['8.8.8.8', '8.8.8.8/32', 'found'],
    ['8.8.8.8', '8.8.8.9/32', 'failed'],
    ['::ffff:8.8.8.8', '8.8.8.0/24', 'found'],
    ['2001:4860:4860::8888', '::/0', 'found'],
    ['2001:4860:4860::8888', '2001:4860:4860::8888/128', 'found'],
    ['2001:4860:4860::8888', '2001:4860:4860::8889/128', 'failed'],
  ])('validates that %s belongs to observed %s', async (ip, prefix, status) => {
    http = upstream({
      routing: () => Response.json({ status: 'ok', data: { prefix, asns: ['15169'] } }),
    });
    const result = await runToolContract(whoisLookupIp, { ip, include_routing: true });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      ip,
      name: 'EXAMPLE',
      ptr_status: 'not_found',
      routing: { status, prefix: status === 'found' ? prefix : null },
    });
    if (status === 'failed') {
      expect(result.structuredContent).toHaveProperty('routing.source_error');
      expect(result.structuredContent).toHaveProperty('routing.recovery');
    }
  });
  it.each([
    ['8.8.8.8/00024', '8.8.8.8', '8.8.8.0/24'],
    ['::ffff:8.8.8.8/00128', '8.8.8.8', '8.8.8.0/24'],
    ['2001:4860:4860::8888/00064', '2001:4860:4860::8888', '2001:4860::/32'],
  ])('uses parsed base for %s and preserves every origin', async (ip, base, prefix) => {
    http = upstream({
      routing: () =>
        Response.json({ status: 'ok', data: { prefix, asns: ['15169', '0003356', '4294967295'] } }),
    });
    const result = await runToolContract(whoisLookupIp, { ip, include_routing: true });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      ip,
      routing: {
        status: 'found',
        prefix,
        origin_asns: ['AS15169', 'AS3356', 'AS4294967295'],
        next_tool: 'whois_lookup_asn',
        source: 'https://stat.ripe.net/data/network-info/data.json',
        snapshot_basis: expect.stringContaining('eight hours'),
      },
    });
    for (const asn of ['AS15169', 'AS3356', 'AS4294967295']) {
      expect(whoisLookupAsn.input.safeParse({ asn }).success).toBe(true);
      expect(textOf(result)).toContain(asn);
    }
    expect(textOf(result)).toContain(prefix);
    expect(textOf(result)).toContain('separate from registry ownership');
    expect(textOf(result)).toContain('eight hours');
    const routingCalls = http.calls.filter(
      (call) => new URL(call.request.url).hostname === 'stat.ripe.net',
    );
    expect(routingCalls).toHaveLength(1);
    expect(new URL(routingCalls[0]!.request.url).searchParams.get('resource')).toBe(base);
    expect(http.calls).toHaveLength(4);
  });
  it('distinguishes successful routing absence from optional failure', async () => {
    http = upstream({
      routing: () => Response.json({ status: 'ok', data: { prefix: '', asns: [] } }),
    });
    const result = await runToolContract(whoisLookupIp, {
      ip: '192.0.2.231',
      include_routing: true,
    });
    expect(result.structuredContent).toMatchObject({
      routing: { status: 'not_found', prefix: null, origin_asns: [] },
    });
    expect(result.structuredContent).not.toHaveProperty('routing.source_error');
    expect(textOf(result)).toContain('Routing Status:** not_found');
    expect(textOf(result)).toContain('whois_lookup_asn');
  });
  it.each(['2001:::1', '192.168.1.1'])(
    'never starts optional work for invalid/excluded %s',
    async (ip) => {
      http = upstream();
      const result = await runToolContract(whoisLookupIp, { ip, include_routing: true });
      expect(result.isError).toBe(true);
      expect(http.calls).toHaveLength(0);
    },
  );
  it('starts no optional work after primary RDAP failure', async () => {
    http = upstream({ rdap: () => new Response(null, { status: 404 }) });
    const result = await runToolContract(whoisLookupIp, { ip: '8.8.8.8', include_routing: true });
    expect(result.structuredContent).toMatchObject({ error: { data: { reason: 'ip_not_found' } } });
    expect(http.calls).toHaveLength(2);
  });
  it.each([
    null,
    [],
    {},
    { status: 'error', data: {} },
    { status: 'ok', data: { prefix: '', asns: ['15169'] } },
    { status: 'ok', data: { prefix: 'bad', asns: ['15169'] } },
    { status: 'ok', data: { prefix: '8.8.8.0/24', asns: ['0'] } },
  ])('retains registry/PTR after malformed optional source %j', async (body) => {
    http = upstream({
      routing: () => Response.json(body),
      dns: (_type, url) =>
        Response.json({
          Status: 0,
          Answer: [{ name: url.searchParams.get('name'), type: 12, TTL: 30, data: 'dns.example.' }],
        }),
    });
    const result = await runToolContract(whoisLookupIp, { ip: '8.8.8.8', include_routing: true });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      name: 'EXAMPLE',
      ptr: 'dns.example',
      routing: {
        status: 'failed',
        prefix: null,
        origin_asns: [],
        source_error: expect.any(String),
        recovery: expect.any(String),
      },
    });
    expect(textOf(result)).toContain('Routing Status:** failed');
    expect(textOf(result)).toContain('Routing Recovery:');
    expect(http.calls).toHaveLength(4);
  });
  it('returns routing detail only when explicitly enabled (#32)', async () => {
    http = upstream();
    const result = await runToolContract(whoisLookupIp, { ip: '8.8.8.8', include_routing: true });
    expect(result.structuredContent).toHaveProperty('routing');
    expect(textOf(result)).toContain('whois_lookup_asn');
  });
  it.each([{}])('keeps the default dependency path for %j', async (options) => {
    http = upstream();
    const result = await runToolContract(whoisLookupIp, { ip: '8.8.8.8', ...options });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).not.toHaveProperty('routing');
    expect(http.calls.map((call) => new URL(call.request.url).hostname)).toEqual([
      'data.iana.org',
      'rdap.test',
      'cloudflare-dns.com',
    ]);
  });
  it('accepts explicit false without adding dependencies (#32)', async () => {
    http = upstream();
    const result = await runToolContract(whoisLookupIp, { ip: '8.8.8.8', include_routing: false });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).not.toHaveProperty('routing');
    expect(http.calls).toHaveLength(3);
  });
});
