/**
 * @fileoverview Service-level tests for RdapService RDAP 404 handling — the
 * upstream "object does not exist" signal must convert to the declared
 * not-found error contracts (or the availability result) without retries.
 * @module tests/services/rdap-service.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { whoisLookupAsn } from '@/mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupDomain } from '@/mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { RdapService } from '@/services/rdap/rdap-service.js';

// --- fixtures -----------------------------------------------------------------

const BOOTSTRAP_DNS = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_IPV4 = 'https://data.iana.org/rdap/ipv4.json';
const BOOTSTRAP_ASN = 'https://data.iana.org/rdap/asn.json';
const RDAP_BASE = 'https://rdap.test';

const notFoundResponse = (): Response => new Response(null, { status: 404 });

/** Fresh service + strict fetch fake wired for 404 paths on every bootstrap source. */
function setup404() {
  const http = createFetchMock([
    {
      match: BOOTSTRAP_DNS,
      respond: Response.json({ services: [[['com'], [RDAP_BASE]]] }),
    },
    {
      match: BOOTSTRAP_IPV4,
      respond: Response.json({ services: [[['8.8.8.0/24'], [RDAP_BASE]]] }),
    },
    {
      match: BOOTSTRAP_ASN,
      respond: Response.json({ services: [[['64512-64534'], [RDAP_BASE]]] }),
    },
    { method: 'GET', match: new RegExp(`^${RDAP_BASE}/`), respond: notFoundResponse() },
  ]);
  http.install();
  return { http, service: new RdapService() };
}

// --- tests --------------------------------------------------------------------

describe('RdapService RDAP 404 handling', () => {
  it('converts an IP netblock 404 into the declared ip_not_found NotFound contract', async () => {
    const { http, service } = setup404();
    try {
      const ctx = createMockContext({ errors: whoisLookupIp.errors });
      await expect(service.lookupIp('8.8.8.8', ctx)).rejects.toMatchObject({
        code: JsonRpcErrorCode.NotFound,
        data: { reason: 'ip_not_found', recovery: { hint: expect.any(String) } },
      });
      // 404 is terminal — exactly one bootstrap fetch + one RDAP call, no retries
      expect(http.calls).toHaveLength(2);
    } finally {
      http.restore();
    }
  });

  it('converts an ASN 404 into the declared asn_not_found NotFound contract', async () => {
    const { http, service } = setup404();
    try {
      const ctx = createMockContext({ errors: whoisLookupAsn.errors });
      await expect(service.lookupAsn('AS64512', ctx)).rejects.toMatchObject({
        code: JsonRpcErrorCode.NotFound,
        data: { reason: 'asn_not_found', recovery: { hint: expect.any(String) } },
      });
      expect(http.calls).toHaveLength(2);
    } finally {
      http.restore();
    }
  });

  it('throws domain_not_found when a registered-TLD domain lookup returns 404', async () => {
    const { service } = setup404();
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    await expect(service.lookupDomain('gone.com', ctx)).rejects.toMatchObject({
      code: JsonRpcErrorCode.NotFound,
      data: { reason: 'domain_not_found', domain: 'gone.com' },
    });
  });

  it('reports a 404 as available:true on checkAvailability', async () => {
    const { service } = setup404();
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    await expect(service.checkAvailability('available.com', ctx)).resolves.toEqual({
      available: true,
    });
  });
});

describe('IP bootstrap prefix boundaries', () => {
  let http: ReturnType<typeof createFetchMock>;
  afterEach(() => http?.restore());

  it.each([
    ['8.8.8.8', false, '0.0.0.0/0', true],
    ['8.8.8.8', false, '8.8.8.8/32', true],
    ['8.8.8.9', false, '8.8.8.8/32', false],
    ['2001:db8::1', true, '::/0', true],
    ['2001:db8::1', true, '2001:db8::1/128', true],
    ['2001:db8::2', true, '2001:db8::1/128', false],
    ['2001:db8:1:ffff::1', true, '2001:db8:1::/48', true],
    ['2001:db8:2::1', true, '2001:db8:1::/48', false],
  ] as const)('routes %s against %s/%s', async (ip, ipv6, cidr, matches) => {
    http = createFetchMock([
      {
        match: `https://data.iana.org/rdap/${ipv6 ? 'ipv6' : 'ipv4'}.json`,
        respond: Response.json({ services: [[[cidr], [RDAP_BASE]]] }),
      },
    ]);
    http.install();
    expect(await new RdapService().findIpRdapServer(ip, ipv6, createMockContext())).toBe(
      matches ? RDAP_BASE : null,
    );
  });
});
