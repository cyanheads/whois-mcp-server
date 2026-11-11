/**
 * @fileoverview Replay public IANA/RIR captures through the real IP contract.
 * @module tests/tools/rdap-captures.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupAsn } from '@/mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import * as doh from '@/services/doh/doh-service.js';
import * as rdap from '@/services/rdap/rdap-service.js';
import notFound from '../fixtures/apnic-not-found.json' with { type: 'json' };
import apnicResearchIp from '../fixtures/apnic-research-ip.json' with { type: 'json' };
import testNet from '../fixtures/arin-test-net.json' with { type: 'json' };
import ipv4 from '../fixtures/iana-ipv4.json' with { type: 'json' };
import ipv6 from '../fixtures/iana-ipv6.json' with { type: 'json' };
import ripeHetznerAsn from '../fixtures/ripe-hetzner-asn.json' with { type: 'json' };
import ripeHetznerIp from '../fixtures/ripe-hetzner-ip.json' with { type: 'json' };
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
    {
      match: 'https://data.iana.org/rdap/asn.json',
      respond: Response.json({ services: [[['24940'], ['https://rdap.db.ripe.net/']]] }),
    },
    { match: 'https://rdap.arin.net/registry/ip/192.0.2.1', respond: Response.json(testNet) },
    { match: 'https://rdap.apnic.net/ip/1.1.1.1', respond: Response.json(apnicResearchIp) },
    { match: 'https://rdap.db.ripe.net/autnum/24940', respond: Response.json(ripeHetznerAsn) },
    { match: 'https://rdap.db.ripe.net/ip/88.198.10.10', respond: Response.json(ripeHetznerIp) },
    {
      match: 'https://rdap.apnic.net/ip/2001:db8::1',
      respond: Response.json(notFound, { status: 404 }),
    },
    {
      match: (request) =>
        request.url.startsWith('https://cloudflare-dns.com/dns-query?') &&
        new URL(request.url).searchParams.get('type') === 'PTR',
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
      cidrs: ['192.0.2.0/24'],
      ip_version: 'v4',
      name: 'TEST-NET-1',
      org_name: 'Internet Assigned Numbers Authority',
      abuse_email: 'abuse@iana.org',
      registration_date: '2009-06-29T12:15:30-04:00',
      last_changed: '2024-05-24T10:19:53-04:00',
      ptr: null,
      ptr_status: 'not_found',
      rdap_source: 'ARIN',
    });
    for (const value of [
      '192.0.2.1/24',
      '192.0.2.0/24',
      'Internet Assigned Numbers Authority',
      'abuse@iana.org',
      '**Registration Date:** 2009-06-29T12:15:30-04:00',
      '**Last Changed:** 2024-05-24T10:19:53-04:00',
      'ARIN',
      'Not available',
    ])
      expect(textOf(result)).toContain(value);
    expect(http.calls).toHaveLength(3);
  });
  it('preserves the APNIC registrant name and direct abuse contact', async () => {
    capturedUpstream();
    const result = await runToolContract(whoisLookupIp, { ip: '1.1.1.1' });
    expect(result.structuredContent).toMatchObject({
      org_name: 'APNIC Research and Development',
      abuse_email: 'helpdesk@apnic.net',
      rdap_source: 'APNIC',
    });
    expect(textOf(result)).toContain('**Organization:** APNIC Research and Development');
    expect(textOf(result)).toContain('**Abuse Email:** helpdesk@apnic.net');
    expect(http.calls).toHaveLength(3);
  });
  it('reports a direct RIPE ASN organization, abuse contact, and object dates', async () => {
    capturedUpstream();
    const result = await runToolContract(whoisLookupAsn, { asn: 'AS24940' });
    expect(result.structuredContent).toEqual({
      asn: 'AS24940',
      rir: 'RIPE',
      org_name: 'Hetzner Online GmbH',
      abuse_email: 'abuse@hetzner.com',
      registration_date: '2002-06-03T08:29:26Z',
      last_changed: '2026-06-30T08:33:15Z',
    });
    const formatted = textOf(result);
    expect(formatted).toContain('**Organization:** Hetzner Online GmbH');
    expect(formatted).toContain('**Abuse Email:** abuse@hetzner.com');
    expect(formatted).toContain('**Registration Date:** 2002-06-03T08:29:26Z');
    expect(formatted).toContain('**Last Changed:** 2026-06-30T08:33:15Z');
    expect(formatted).not.toContain('HOS-GUN');
    expect(http.calls).toHaveLength(2);
  });
  it('omits a RIPE IP organization nested under an abuse contact', async () => {
    capturedUpstream();
    const result = await runToolContract(whoisLookupIp, { ip: '88.198.10.10' });
    expect(result.structuredContent).toMatchObject({
      abuse_email: 'abuse@hetzner.com',
      rdap_source: 'RIPE',
    });
    expect(result.structuredContent).not.toHaveProperty('org_name');
    expect(textOf(result)).not.toContain('**Organization:**');
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
          code: JsonRpcErrorCode.NotFound,
          data: {
            reason: 'ip_no_rdap_route',
            retryable: false,
            recovery: { hint: expect.any(String) },
          },
        },
      });
      expect(http.calls).toHaveLength(1);
    },
  );
});
