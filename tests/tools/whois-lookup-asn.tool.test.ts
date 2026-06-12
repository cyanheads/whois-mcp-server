/**
 * @fileoverview Tests for whois_lookup_asn tool.
 * @module tests/tools/whois-lookup-asn.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupAsn } from '@/mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import type { NormalizedAsn } from '@/services/rdap/types.js';

// --- service mock -----------------------------------------------------------

vi.mock('@/services/rdap/rdap-service.js', () => {
  const mockService = {
    lookupAsn: vi.fn(),
  };
  return {
    getRdapService: () => mockService,
    __mockService: mockService,
  };
});

async function getRdapMock() {
  const mod = await import('@/services/rdap/rdap-service.js');
  return (mod as unknown as { __mockService: { lookupAsn: ReturnType<typeof vi.fn> } })
    .__mockService;
}

// --- fixtures ---------------------------------------------------------------

const googleAsn: NormalizedAsn = {
  asn: 'AS15169',
  handle: 'AS15169',
  start_autnum: 15169,
  end_autnum: 15169,
  name: 'GOOGLE',
  type: 'DIRECT ALLOCATION',
  country: 'US',
  org_name: 'Google LLC',
  rir: 'ARIN',
};

const asnRange: NormalizedAsn = {
  asn: 'AS64496',
  start_autnum: 64496,
  end_autnum: 64511,
  org_name: 'Documentation Range',
  rir: 'ARIN',
};

// --- tests ------------------------------------------------------------------

describe('whoisLookupAsn', () => {
  let rdap: { lookupAsn: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    rdap = await getRdapMock();
    vi.clearAllMocks();
  });

  it('resolves AS-prefixed ASN to org name and RIR', async () => {
    rdap.lookupAsn.mockResolvedValue(googleAsn);
    const ctx = createMockContext({ errors: whoisLookupAsn.errors });
    const input = whoisLookupAsn.input.parse({ asn: 'AS15169' });
    const result = await whoisLookupAsn.handler(input, ctx);

    expect(result.asn).toBe('AS15169');
    expect(result.org_name).toBe('Google LLC');
    expect(result.rir).toBe('ARIN');
    expect(result.country).toBe('US');
    expect(result.start_autnum).toBe(15169);
  });

  it('resolves bare integer ASN format', async () => {
    rdap.lookupAsn.mockResolvedValue(googleAsn);
    const ctx = createMockContext({ errors: whoisLookupAsn.errors });
    const input = whoisLookupAsn.input.parse({ asn: '15169' });
    const result = await whoisLookupAsn.handler(input, ctx);
    expect(result.asn).toBe('AS15169');
  });

  it('propagates invalid_asn error from service for non-numeric input', async () => {
    const { McpError, JsonRpcErrorCode } = await import('@cyanheads/mcp-ts-core/errors');
    const invalidErr = new McpError(JsonRpcErrorCode.ValidationError, 'invalid ASN', {
      reason: 'invalid_asn',
    });
    rdap.lookupAsn.mockRejectedValue(invalidErr);
    const ctx = createMockContext({ errors: whoisLookupAsn.errors });
    const input = whoisLookupAsn.input.parse({ asn: 'NOTANASN' });
    await expect(whoisLookupAsn.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_asn' },
    });
  });

  it('propagates asn_not_found error when ASN has no RDAP record', async () => {
    const { McpError, JsonRpcErrorCode } = await import('@cyanheads/mcp-ts-core/errors');
    const notFoundErr = new McpError(JsonRpcErrorCode.NotFound, 'ASN not found', {
      reason: 'asn_not_found',
    });
    rdap.lookupAsn.mockRejectedValue(notFoundErr);
    const ctx = createMockContext({ errors: whoisLookupAsn.errors });
    const input = whoisLookupAsn.input.parse({ asn: 'AS99999999' });
    await expect(whoisLookupAsn.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'asn_not_found' },
    });
  });

  it('handles sparse ASN record (only required fields)', async () => {
    const sparse: NormalizedAsn = { asn: 'AS12345' };
    rdap.lookupAsn.mockResolvedValue(sparse);
    const ctx = createMockContext({ errors: whoisLookupAsn.errors });
    const input = whoisLookupAsn.input.parse({ asn: '12345' });
    const result = await whoisLookupAsn.handler(input, ctx);

    expect(result.asn).toBe('AS12345');
    expect(result.org_name).toBeUndefined();
    expect(result.rir).toBeUndefined();
  });

  it('formats ASN result with single ASN range', () => {
    const blocks = whoisLookupAsn.format!(googleAsn);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('AS15169');
    expect(text).toContain('Google LLC');
    expect(text).toContain('ARIN');
    expect(text).toContain('GOOGLE');
    // Single ASN — range shows same number
    expect(text).toContain('15169');
  });

  it('formats ASN range result spanning multiple ASNs', () => {
    const blocks = whoisLookupAsn.format!(asnRange);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('AS64496');
    expect(text).toContain('64496');
    expect(text).toContain('64511');
  });
});
