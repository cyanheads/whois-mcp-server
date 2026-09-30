/**
 * @fileoverview Replay public IANA/RIR captures through the real IP contract.
 * @module tests/tools/rdap-captures.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import * as doh from '@/services/doh/doh-service.js';
import * as rdap from '@/services/rdap/rdap-service.js';
import notFound from '../fixtures/apnic-not-found.json' with { type: 'json' };
import testNet from '../fixtures/arin-test-net.json' with { type: 'json' };
import ipv4 from '../fixtures/iana-ipv4.json' with { type: 'json' };
import ipv6 from '../fixtures/iana-ipv6.json' with { type: 'json' };
import { textOf } from '../helpers/upstream.js';

let http: ReturnType<typeof createFetchMock>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
});

function capturedUpstream() {
  vi.spyOn(rdap, 'getRdapService').mockReturnValue(new rdap.RdapService());
  vi.spyOn(doh, 'getDohService').mockReturnValue(new doh.DohService());
  http = createFetchMock([
    { match: 'https://data.iana.org/rdap/ipv4.json', respond: Response.json(ipv4) },
    { match: 'https://data.iana.org/rdap/ipv6.json', respond: Response.json(ipv6) },
    { match: 'https://rdap.arin.net/registry/ip/192.0.2.1', respond: Response.json(testNet) },
    {
      match: 'https://rdap.apnic.net/ip/2001:db8::1',
      respond: Response.json(notFound, { status: 404 }),
    },
    {
      match: 'https://cloudflare-dns.com/dns-query?name=1.2.0.192.in-addr.arpa&type=PTR',
      respond: Response.json({ Status: 3 }),
    },
  ]);
  http.install();
}

describe('captured RDAP outcomes', () => {
  it('retains useful TEST-NET registration, nested abuse entity, and PTR absence', async () => {
    capturedUpstream();
    const result = await runToolContract(whoisLookupIp, { ip: '192.0.2.1/24' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toEqual({
      ip: '192.0.2.1/24',
      handle: 'NET-192-0-2-0-1',
      start_address: '192.0.2.0',
      end_address: '192.0.2.255',
      cidr: '192.0.2.0/24',
      ip_version: 'v4',
      name: 'TEST-NET-1',
      org_name: 'Internet Assigned Numbers Authority',
      abuse_email: 'abuse@iana.org',
      ptr: null,
      rdap_source: 'ARIN',
    });
    for (const value of [
      '192.0.2.1/24',
      '192.0.2.0/24',
      'Internet Assigned Numbers Authority',
      'abuse@iana.org',
      'ARIN',
      'Not available',
    ])
      expect(textOf(result)).toContain(value);
    expect(http.calls).toHaveLength(3);
  });
  it('retains the documentation IPv6 ip_not_found envelope without retry or PTR', async () => {
    capturedUpstream();
    const result = await runToolContract(whoisLookupIp, { ip: '2001:db8::1' });
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.NotFound,
        data: { reason: 'ip_not_found', recovery: { hint: expect.any(String) } },
      },
    });
    expect(textOf(result)).toContain('Recovery:');
    expect(http.calls).toHaveLength(2);
  });
  it.each(['224.0.0.1', '::', '::10'])(
    'preserves actual missing-bootstrap-route outcome for %s',
    async (ip) => {
      capturedUpstream();
      const result = await runToolContract(whoisLookupIp, { ip });
      expect(result.structuredContent).toMatchObject({
        error: {
          code: JsonRpcErrorCode.ServiceUnavailable,
          message: 'No RIR RDAP server found for this IP address range.',
        },
      });
      expect(http.calls).toHaveLength(1);
    },
  );
});
