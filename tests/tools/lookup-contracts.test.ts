/**
 * @fileoverview Real-service characterization and regression tests for lookup contracts.
 * @module tests/tools/lookup-contracts.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisCheckAvailability } from '@/mcp-server/tools/definitions/whois-check-availability.tool.js';
import { whoisLookupAsn } from '@/mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { validateIp } from '@/services/rdap/rdap-service.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
});

describe('lookup characterization', () => {
  it.each(['15169', 'AS15169', 'as0015169', '+15169', 'AS 15169'])(
    'normalizes working ASN %s',
    async (asn) => {
      http = upstream();
      const result = await runToolContract(whoisLookupAsn, { asn });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        asn: 'AS15169',
        name: 'EXAMPLE',
        rir: 'ARIN',
      });
      expect(textOf(result)).toContain('AS15169');
      expect(textOf(result)).toContain('ARIN');
      expect(http.calls.map((call) => new URL(call.request.url).pathname)).toEqual([
        '/rdap/asn.json',
        '/autnum/15169',
      ]);
    },
  );

  it.each(['8.8.8.8', '8.8.8.8/24', '2001:4860:4860::8888'])(
    'preserves query and base-address lookup for %s',
    async (ip) => {
      http = upstream({
        dns: () =>
          Response.json({
            Status: 0,
            Answer: [{ type: 12, name: 'ptr', TTL: 60, data: 'dns.example.' }],
          }),
      });
      const result = await runToolContract(whoisLookupIp, { ip });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        ip,
        name: 'EXAMPLE',
        rdap_source: 'ARIN',
        ptr: 'dns.example',
      });
      expect(textOf(result)).toContain(ip);
      expect(textOf(result)).toContain('dns.example');
      expect(http.calls[1]?.request.url).toBe(`https://rdap.test/ip/${ip.split('/')[0]}`);
    },
  );

  it('retains no RDAP coverage as unknown availability data', async () => {
    http = upstream({ coverage: false });
    const result = await runToolContract(whoisCheckAvailability, { domain: 'example.local' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toEqual({
      domain: 'example.local',
      available: null,
      rdap_coverage: false,
    });
    expect(textOf(result)).toContain('Unknown');
    expect(http.calls).toHaveLength(1);
  });

  it.each(['ip', 'asn'] as const)('preserves %s 404 recovery and never retries', async (kind) => {
    http = upstream({ rdap: () => new Response(null, { status: 404 }) });
    const result =
      kind === 'ip'
        ? await runToolContract(whoisLookupIp, { ip: '8.8.8.8' })
        : await runToolContract(whoisLookupAsn, { asn: 'AS15169' });
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.NotFound,
        data: { reason: `${kind}_not_found`, recovery: { hint: expect.any(String) } },
      },
    });
    expect(textOf(result)).toContain('Recovery:');
    expect(http.calls).toHaveLength(2);
  });
});

describe('ASN regression #5', () => {
  it.each([
    'AS15169abc',
    '1.5',
    '1e3',
    'AS+ 15169',
    '+ 15169',
    '151 69',
    'AS++15169',
    'A15169',
    '0',
    '-1',
    '4294967296',
    '9007199254740993',
    'AS',
    '',
  ])('rejects the entire invalid token %j before fetch with recovery', async (asn) => {
    http = upstream();
    const result = await runToolContract(whoisLookupAsn, { asn });
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: { reason: 'invalid_asn', recovery: { hint: expect.any(String) } },
      },
    });
    expect(textOf(result)).toContain('Recovery:');
    expect(http.calls).toHaveLength(0);
  });
  it.each([
    [' AS15169 ', 'AS15169'],
    ['\tas +0015169\n', 'AS15169'],
    ['1', 'AS1'],
    ['4294967295', 'AS4294967295'],
  ])('accepts complete in-range token %j', async (asn, normalized) => {
    http = upstream();
    const result = await runToolContract(whoisLookupAsn, { asn });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ asn: normalized });
    expect(textOf(result)).toContain(normalized);
  });
  it('rejects a boolean without fetching', async () => {
    http = upstream();
    // @ts-expect-error Deliberately exercise wrong-type input at the contract boundary.
    const result = await runToolContract(whoisLookupAsn, { asn: true });
    expect(result.structuredContent).toMatchObject({
      error: { code: JsonRpcErrorCode.InvalidParams, data: { reason: 'invalid_arguments' } },
    });
    expect(http.calls).toHaveLength(0);
  });
});

describe('IP regression #6', () => {
  it.each([
    '8.8.8.8/24/garbage',
    '8.8.8.8/24garbage',
    '8.8.8.8/24.5',
    '8.8.8.8/+24',
    '8.8.8.8/ 24',
    '8.8.8.8/24\n',
    '8.8.8.8/24\r',
    '8.8.8.8/',
    '8.8.8.8/33',
    '8.8.8.8/-1',
    '8.8.8.8//',
    ' 8.8.8.8',
    '8.8.8.8 ',
    '08.8.8.8',
    '256.1.1.1',
    '2001:::1',
    ':::',
    '1:2:3',
    '12345::1',
    '1::2::3',
    '1:2:3:4:5:6:7:8:9',
    '1:2:3:4:5:6:7::8',
    '2001:db8::1/129',
    '2001:db8::1%en0',
    '[2001:db8::1]',
  ])('rejects malformed IP %j without fetch', async (ip) => {
    http = upstream();
    expect(validateIp(ip).valid).toBe(false);
    const result = await runToolContract(whoisLookupIp, { ip });
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: { reason: 'invalid_ip', recovery: { hint: expect.any(String) } },
      },
    });
    expect(textOf(result)).toContain('Recovery:');
    expect(http.calls).toHaveLength(0);
  });

  it.each([
    '0.0.0.0',
    '0.255.255.255',
    '10.0.0.0',
    '10.255.255.255',
    '100.64.0.0',
    '100.127.255.255',
    '127.0.0.0',
    '127.255.255.255',
    '169.254.0.0',
    '169.254.255.255',
    '172.16.0.0',
    '172.31.255.255',
    '192.168.0.0',
    '192.168.255.255',
    '255.0.0.0',
    '255.255.255.255',
    '::1',
    '0:0:0:0:0:0:0:1',
    '0000:0000:0000:0000:0000:0000:0000:0001',
    'fc00::',
    'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'fe80::',
    'fe90::1',
    'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    '::ffff:192.168.1.1',
    '0:0:0:0:0:ffff:c0a8:101',
    '::ffff:10.1.2.3/128',
  ])('excludes numeric policy address %s', async (ip) => {
    http = upstream();
    const result = await runToolContract(whoisLookupIp, { ip });
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: { reason: 'private_range', recovery: { hint: expect.any(String) } },
      },
    });
    expect(textOf(result)).toContain('Recovery:');
    expect(http.calls).toHaveLength(0);
  });

  it.each([
    '1.0.0.0',
    '9.255.255.255',
    '11.0.0.0',
    '100.63.255.255',
    '100.128.0.0',
    '126.255.255.255',
    '128.0.0.0',
    '169.253.255.255',
    '169.255.0.0',
    '172.15.255.255',
    '172.32.0.0',
    '192.167.255.255',
    '192.169.0.0',
    '254.255.255.255',
    '192.0.2.1',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '240.0.0.1',
    '::',
    '::10',
    '2001:db8::1',
    'fbff:ffff::1',
    'fe00::1',
    'fe7f:ffff::1',
    'fec0::1',
    '8.8.8.8/0',
    '8.8.8.8/32',
    '2001:db8::1/0',
    '2001:db8::1/128',
  ])('leaves %s eligible for RDAP', async (ip) => {
    http = upstream();
    const result = await runToolContract(whoisLookupIp, { ip });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ ip, ptr: null });
    expect(http.calls).toHaveLength(3);
  });

  it.each(['::ffff:8.8.8.8', '::ffff:0808:0808', '0:0:0:0:0:FFFF:808:808/120'])(
    'routes mapped IPv4 %s to IPv4 RDAP and PTR',
    async (ip) => {
      http = upstream();
      const result = await runToolContract(whoisLookupIp, { ip });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ ip });
      expect(http.calls[0]?.request.url).toBe('https://data.iana.org/rdap/ipv4.json');
      expect(http.calls[1]?.request.url).toBe('https://rdap.test/ip/8.8.8.8');
      expect(new URL(http.calls[2]!.request.url).searchParams.get('name')).toBe(
        '8.8.8.8.in-addr.arpa',
      );
    },
  );

  it.each(['2001:db8::192.0.2.1', '2001:0db8:0:0:0:0:c000:0201', '2001:db8::c000:201/64'])(
    'uses 32 PTR nibbles for ordinary IPv6 %s',
    async (ip) => {
      http = upstream();
      const result = await runToolContract(whoisLookupIp, { ip });
      expect(result.isError).not.toBe(true);
      expect(new URL(http.calls[2]!.request.url).searchParams.get('name')).toBe(
        `${'20010db80000000000000000c0000201'.split('').reverse().join('.')}.ip6.arpa`,
      );
    },
  );
});

describe('RIR hostname regression #12', () => {
  it.each(['arin', 'ripe', 'apnic', 'lacnic', 'afrinic'])(
    'labels %s only from a parsed self-link hostname',
    async (rir) => {
      for (const kind of ['ip', 'asn'] as const) {
        for (const [href, expected] of [
          [`https://rdap.${rir.toUpperCase()}.NET./object`, rir.toUpperCase()],
          [`https://${rir}.net/object`, rir.toUpperCase()],
          [`https://evil.example/path/${rir}.net`, undefined],
          [`https://evil.example/?source=${rir}.net`, undefined],
          [`https://${rir}.net@evil.example/object`, undefined],
          [`https://${rir}.net.evil.example/object`, undefined],
          [`https://not${rir}.net/object`, undefined],
          [`not a URL ${rir}.net`, undefined],
          [undefined, undefined],
        ]) {
          http = upstream({
            rdap: () =>
              Response.json({
                name: 'EXAMPLE',
                links:
                  href === undefined
                    ? [{ rel: 'alternate', href: `https://${rir}.net` }]
                    : [{ rel: 'self', href }],
              }),
          });
          const result =
            kind === 'ip'
              ? await runToolContract(whoisLookupIp, { ip: '8.8.8.8' })
              : await runToolContract(whoisLookupAsn, { asn: '15169' });
          expect(result.isError, `${kind} ${href}`).not.toBe(true);
          if (expected) {
            expect(result.structuredContent).toHaveProperty(
              kind === 'ip' ? 'rdap_source' : 'rir',
              expected,
            );
            expect(textOf(result)).toContain(expected);
          } else {
            expect(result.structuredContent).not.toHaveProperty(
              kind === 'ip' ? 'rdap_source' : 'rir',
            );
            expect(textOf(result)).not.toContain(kind === 'ip' ? '**RIR Source:**' : '**RIR:**');
          }
          http.restore();
          vi.restoreAllMocks();
        }
      }
    },
  );
});
