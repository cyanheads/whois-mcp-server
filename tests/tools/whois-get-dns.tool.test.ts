/**
 * @fileoverview Tests for whois_get_dns tool.
 * @module tests/tools/whois-get-dns.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { whoisGetDns } from '@/mcp-server/tools/definitions/whois-get-dns.tool.js';
import type { DnsLookupResult } from '@/services/doh/types.js';

// --- service mock -----------------------------------------------------------

vi.mock('@/services/doh/doh-service.js', () => {
  const mockService = {
    lookup: vi.fn(),
  };
  return {
    getDohService: () => mockService,
    __mockService: mockService,
  };
});

async function getDohMock() {
  const mod = await import('@/services/doh/doh-service.js');
  return (mod as unknown as { __mockService: { lookup: ReturnType<typeof vi.fn> } }).__mockService;
}

// --- fixtures ---------------------------------------------------------------

const noRecordResult: DnsLookupResult = {
  domain: 'example.com',
  nxdomain: false,
  records: [],
  source: 'cloudflare',
};

// CRITICAL: NXDOMAIN is DATA not an error — nxdomain: true in result, not thrown
const nxdomainResult: DnsLookupResult = {
  domain: 'does-not-exist-in-dns.example',
  nxdomain: true,
  records: [],
  source: 'cloudflare',
};

const dnsWithRecords: DnsLookupResult = {
  domain: 'example.com',
  nxdomain: false,
  records: [
    { type: 'A', name: 'example.com', ttl: 300, data: '93.184.216.34' },
    { type: 'MX', name: 'example.com', ttl: 3600, data: '10 mail.example.com.' },
    { type: 'NS', name: 'example.com', ttl: 3600, data: 'ns1.example.com.' },
    { type: 'TXT', name: 'example.com', ttl: 3600, data: '"v=spf1 -all"' },
  ],
  source: 'cloudflare',
};

// --- tests ------------------------------------------------------------------

describe('whoisGetDns', () => {
  let doh: { lookup: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    doh = await getDohMock();
    vi.clearAllMocks();
  });

  it('returns DNS records for a domain with a valid response', async () => {
    doh.lookup.mockResolvedValue(dnsWithRecords);
    const ctx = createMockContext({ errors: whoisGetDns.errors });
    const input = whoisGetDns.input.parse({ domain: 'example.com' });
    const result = await whoisGetDns.handler(input, ctx);

    expect(result.domain).toBe('example.com');
    expect(result.nxdomain).toBe(false);
    expect(result.source).toBe('cloudflare');
    expect(result.records).toHaveLength(4);
    const aRecord = result.records.find((r) => r.type === 'A');
    expect(aRecord?.data).toBe('93.184.216.34');
  });

  // CRITICAL: NXDOMAIN → data with nxdomain: true, NOT a thrown error
  it('returns nxdomain: true as data (not an error) when domain has no DNS', async () => {
    doh.lookup.mockResolvedValue(nxdomainResult);
    const ctx = createMockContext({ errors: whoisGetDns.errors });
    const input = whoisGetDns.input.parse({ domain: 'does-not-exist-in-dns.example' });

    // Must resolve, not reject
    const result = await whoisGetDns.handler(input, ctx);
    expect(result.nxdomain).toBe(true);
    expect(result.records).toEqual([]);
  });

  it('uses default types [A, AAAA, MX, TXT, NS] when types not specified', async () => {
    doh.lookup.mockResolvedValue(noRecordResult);
    const ctx = createMockContext({ errors: whoisGetDns.errors });
    const input = whoisGetDns.input.parse({ domain: 'example.com' });

    await whoisGetDns.handler(input, ctx);
    const calledTypes = doh.lookup.mock.calls[0]?.[1] as string[];
    expect(calledTypes).toEqual(['A', 'AAAA', 'MX', 'TXT', 'NS']);
  });

  it('passes requested types to the DoH service', async () => {
    doh.lookup.mockResolvedValue(noRecordResult);
    const ctx = createMockContext({ errors: whoisGetDns.errors });
    const input = whoisGetDns.input.parse({ domain: 'example.com', types: ['A', 'CAA'] });

    await whoisGetDns.handler(input, ctx);
    const calledTypes = doh.lookup.mock.calls[0]?.[1] as string[];
    expect(calledTypes).toEqual(['A', 'CAA']);
  });

  it('throws invalid_domain for input without a dot', async () => {
    const ctx = createMockContext({ errors: whoisGetDns.errors });
    const input = whoisGetDns.input.parse({ domain: 'nodot' });
    await expect(whoisGetDns.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_domain' },
    });
  });

  it('formats output with grouped record types and all key fields', () => {
    const blocks = whoisGetDns.format!(dnsWithRecords);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('example.com');
    expect(text).toContain('93.184.216.34');
    expect(text).toContain('cloudflare');
    expect(text).toContain('No');
    // Each record's data, name, and TTL must appear
    expect(text).toContain('ns1.example.com');
    expect(text).toContain('TTL');
  });

  it('formats NXDOMAIN result correctly', () => {
    const blocks = whoisGetDns.format!(nxdomainResult);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Yes');
    expect(text).toContain('does not exist');
  });

  it('handles sparse upstream payload — no Answer records', () => {
    const sparse: DnsLookupResult = {
      domain: 'sparse.com',
      nxdomain: false,
      records: [],
      source: 'cloudflare',
    };
    doh.lookup.mockResolvedValue(sparse);
    const blocks = whoisGetDns.format!(sparse);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('sparse.com');
    expect(text).toContain('No records');
  });

  it('formats output with nextdns source correctly', () => {
    const nextdnsResult: DnsLookupResult = {
      domain: 'example.com',
      nxdomain: false,
      records: [
        { type: 'CAA', name: 'example.com', ttl: 86400, data: '0 issue "letsencrypt.org"' },
      ],
      source: 'nextdns',
    };
    const blocks = whoisGetDns.format!(nextdnsResult);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('nextdns');
  });
});
