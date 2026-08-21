/**
 * @fileoverview Service-level tests for RdapService RDAP 404 handling — the
 * upstream "object does not exist" signal must convert to the declared
 * not-found error contracts (or the availability result) without retries.
 * @module tests/services/rdap-service.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
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
