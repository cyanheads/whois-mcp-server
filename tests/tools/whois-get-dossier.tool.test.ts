/**
 * @fileoverview Tests for whois_get_dossier tool — one-call domain triage.
 * Covers: happy path, DNS-only partial, RDAP-only partial, both-legs-failed throw,
 * inferred signals, nxdomain leg, and format.
 * @module tests/tools/whois-get-dossier.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { whoisGetDossier } from '@/mcp-server/tools/definitions/whois-get-dossier.tool.js';
import type { DnsLookupResult } from '@/services/doh/types.js';
import type { NormalizedDomain } from '@/services/rdap/types.js';

// --- service mocks ----------------------------------------------------------

vi.mock('@/services/rdap/rdap-service.js', () => {
  const mockService = { lookupDomain: vi.fn() };
  return { getRdapService: () => mockService, __mockService: mockService };
});

vi.mock('@/services/doh/doh-service.js', () => {
  const mockService = { lookup: vi.fn() };
  return { getDohService: () => mockService, __mockService: mockService };
});

async function getRdapMock() {
  const mod = await import('@/services/rdap/rdap-service.js');
  return (mod as unknown as { __mockService: { lookupDomain: ReturnType<typeof vi.fn> } })
    .__mockService;
}

async function getDohMock() {
  const mod = await import('@/services/doh/doh-service.js');
  return (mod as unknown as { __mockService: { lookup: ReturnType<typeof vi.fn> } }).__mockService;
}

// --- fixtures ---------------------------------------------------------------

const rdapRecord: NormalizedDomain = {
  domain: 'github.com',
  rdap_coverage: true,
  registrar: 'MarkMonitor Inc.',
  created_date: '2007-01-26T00:00:00Z',
  expiry_date: '2028-01-26T00:00:00Z',
  status: ['clientDeleteProhibited', 'clientTransferProhibited'],
  nameservers: ['ns1.github.com', 'ns2.github.com'],
  dnssec_signed: false,
  registrant_redacted: true,
};

const dnsResult: DnsLookupResult = {
  domain: 'github.com',
  nxdomain: false,
  records: [
    { type: 'A', name: 'github.com', ttl: 60, data: '140.82.114.4' },
    { type: 'MX', name: 'github.com', ttl: 3600, data: '1 aspmx.l.google.com.' },
    { type: 'NS', name: 'github.com', ttl: 3600, data: 'ns1.p16.dynect.net.' },
    { type: 'TXT', name: 'github.com', ttl: 3600, data: '"v=spf1 ip4:192.30.252.0/22"' },
  ],
  source: 'cloudflare',
};

const nxdomainDnsResult: DnsLookupResult = {
  domain: 'nonexistent.example.com',
  nxdomain: true,
  records: [],
  source: 'cloudflare',
};

// --- tests ------------------------------------------------------------------

describe('whoisGetDossier', () => {
  let rdap: { lookupDomain: ReturnType<typeof vi.fn> };
  let doh: { lookup: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    rdap = await getRdapMock();
    doh = await getDohMock();
    vi.clearAllMocks();
  });

  it('returns combined dossier when both RDAP and DNS legs succeed', async () => {
    rdap.lookupDomain.mockResolvedValue(rdapRecord);
    doh.lookup.mockResolvedValue(dnsResult);
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'github.com' });
    const result = await whoisGetDossier.handler(input, ctx);

    expect(result.domain).toBe('github.com');
    expect(result.rdap_coverage).toBe(true);
    expect(result.registered).toBe(true);
    expect(result.registrar).toBe('MarkMonitor Inc.');
    expect(result.a_records).toContain('140.82.114.4');
    // Inferred from MX: aspmx.l.google.com → Google Workspace
    expect(result.mx_provider).toBe('Google Workspace');
    // Inferred from NS: ns1.p16.dynect.net → dynect (fallback to 2nd-level)
    expect(result.ns_provider).toBeDefined();
    expect(result.rdap_source_error).toBeUndefined();
    expect(result.dns_source_error).toBeUndefined();
  });

  it('computes age_days from created_date', async () => {
    rdap.lookupDomain.mockResolvedValue(rdapRecord);
    doh.lookup.mockResolvedValue(dnsResult);
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'github.com' });
    const result = await whoisGetDossier.handler(input, ctx);

    expect(typeof result.age_days).toBe('number');
    expect((result.age_days as number) > 365 * 5).toBe(true); // github.com is old
  });

  // CRITICAL: single DNS leg failure → partial result, NOT a thrown error
  it('surfaces rdap_source_error and nulls RDAP fields when RDAP leg fails', async () => {
    rdap.lookupDomain.mockRejectedValue(new Error('RDAP timeout'));
    doh.lookup.mockResolvedValue(dnsResult);
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'github.com' });
    const result = await whoisGetDossier.handler(input, ctx);

    // Must not throw — partial result
    expect(result.rdap_coverage).toBeNull();
    expect(result.registered).toBeNull();
    expect(result.rdap_source_error).toContain('RDAP timeout');
    // DNS data should still be populated
    expect(result.a_records).toContain('140.82.114.4');
  });

  // CRITICAL: single RDAP leg failure → partial result, NOT a thrown error
  it('surfaces dns_source_error and empty DNS fields when DNS leg fails', async () => {
    rdap.lookupDomain.mockResolvedValue(rdapRecord);
    doh.lookup.mockRejectedValue(new Error('DoH unreachable'));
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'github.com' });
    const result = await whoisGetDossier.handler(input, ctx);

    // Must not throw — partial result
    expect(result.dns_source_error).toContain('DoH unreachable');
    expect(result.a_records).toEqual([]);
    expect(result.ns_provider).toBeNull();
    // RDAP data should still be populated
    expect(result.registered).toBe(true);
    expect(result.registrar).toBe('MarkMonitor Inc.');
  });

  // CRITICAL: both legs fail → throws both_legs_failed (ServiceUnavailable)
  it('throws both_legs_failed when both RDAP and DNS legs fail', async () => {
    rdap.lookupDomain.mockRejectedValue(new Error('RDAP down'));
    doh.lookup.mockRejectedValue(new Error('DNS down'));
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'github.com' });
    await expect(whoisGetDossier.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'both_legs_failed' },
    });
  });

  it('returns dns_nxdomain: true when DNS leg reports NXDOMAIN', async () => {
    rdap.lookupDomain.mockResolvedValue(rdapRecord);
    doh.lookup.mockResolvedValue(nxdomainDnsResult);
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'github.com' });
    const result = await whoisGetDossier.handler(input, ctx);

    expect(result.dns_nxdomain).toBe(true);
    expect(result.a_records).toEqual([]);
    expect(result.mx_records).toEqual([]);
  });

  it('throws invalid_domain for input without a dot', async () => {
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'nodot' });
    await expect(whoisGetDossier.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_domain' },
    });
  });

  it('infers Cloudflare as NS provider from cloudflare NS records', async () => {
    const cloudflareNs: DnsLookupResult = {
      domain: 'cloudflare.com',
      nxdomain: false,
      records: [{ type: 'NS', name: 'cloudflare.com', ttl: 3600, data: 'ns1.cloudflare.com.' }],
      source: 'cloudflare',
    };
    rdap.lookupDomain.mockResolvedValue({ ...rdapRecord, domain: 'cloudflare.com' });
    doh.lookup.mockResolvedValue(cloudflareNs);
    const ctx = createMockContext({ errors: whoisGetDossier.errors });
    const input = whoisGetDossier.input.parse({ domain: 'cloudflare.com' });
    const result = await whoisGetDossier.handler(input, ctx);
    expect(result.ns_provider).toBe('Cloudflare');
  });

  it('formats dossier result with registration, DNS, and signals sections', () => {
    // Construct a realistic complete result object
    const output = {
      domain: 'github.com',
      rdap_coverage: true,
      registered: true,
      registrar: 'MarkMonitor Inc.',
      created_date: '2007-01-26T00:00:00Z',
      expiry_date: '2028-01-26T00:00:00Z',
      age_days: 6000,
      dnssec_signed: false,
      privacy_redacted: true,
      status: ['clientDeleteProhibited'],
      nameservers: ['ns1.github.com'],
      a_records: ['140.82.114.4'],
      mx_records: ['aspmx.l.google.com'],
      ns_records: ['ns1.p16.dynect.net'],
      txt_records: ['"v=spf1"'],
      dns_nxdomain: false,
      ns_provider: 'Dyn DNS',
      mx_provider: 'Google Workspace',
    };
    const blocks = whoisGetDossier.format!(output);
    const text = (blocks[0] as { text: string }).text;

    expect(text).toContain('github.com');
    expect(text).toContain('MarkMonitor Inc.');
    expect(text).toContain('6000 days');
    expect(text).toContain('140.82.114.4');
    expect(text).toContain('Google Workspace');
    expect(text).toContain('Dyn DNS');
    // Both sections must be present
    expect(text).toContain('Registration');
    expect(text).toContain('DNS');
    expect(text).toContain('Signals');
  });

  it('formats partial result (RDAP failed) with error message in registration section', () => {
    const output = {
      domain: 'partial.com',
      rdap_coverage: null,
      registered: null,
      age_days: null,
      dnssec_signed: null,
      privacy_redacted: null,
      status: [],
      nameservers: [],
      a_records: ['1.2.3.4'],
      mx_records: [],
      ns_records: [],
      txt_records: [],
      dns_nxdomain: false,
      ns_provider: null,
      mx_provider: null,
      rdap_source_error: 'RDAP timeout after 5000ms',
    };
    const blocks = whoisGetDossier.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('RDAP timeout after 5000ms');
    expect(text).toContain('1.2.3.4');
  });
});
