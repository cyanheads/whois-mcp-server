/**
 * @fileoverview Tests for whois_check_availability tool.
 * @module tests/tools/whois-check-availability.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { whoisCheckAvailability } from '@/mcp-server/tools/definitions/whois-check-availability.tool.js';
import type { NormalizedDomain } from '@/services/rdap/types.js';

// --- service mock -----------------------------------------------------------

vi.mock('@/services/rdap/rdap-service.js', () => {
  const mockService = {
    checkAvailability: vi.fn(),
  };
  return {
    getRdapService: () => mockService,
    __mockService: mockService,
  };
});

async function getRdapMock() {
  const mod = await import('@/services/rdap/rdap-service.js');
  return (mod as unknown as { __mockService: { checkAvailability: ReturnType<typeof vi.fn> } })
    .__mockService;
}

// --- fixtures ---------------------------------------------------------------

const registeredRecord: NormalizedDomain = {
  domain: 'taken.com',
  rdap_coverage: true,
  registrar: 'Big Registrar LLC',
  expiry_date: '2026-01-01T00:00:00Z',
  status: ['clientTransferProhibited'],
  nameservers: ['ns1.taken.com'],
  dnssec_signed: false,
  registrant_redacted: true,
};

// --- tests ------------------------------------------------------------------

describe('whoisCheckAvailability', () => {
  let rdap: { checkAvailability: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    rdap = await getRdapMock();
    vi.clearAllMocks();
  });

  // RDAP 404 is record absence, never evidence of registration eligibility.
  it('returns not_found/null when RDAP returns 404', async () => {
    rdap.checkAvailability.mockResolvedValue({
      available: null,
      registration_status: 'not_found',
      rdap_coverage: true,
    });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'unregistered-domain-xyz.com' });
    const result = await whoisCheckAvailability.handler(input, ctx);

    expect(result.available).toBeNull();
    expect(result.registration_status).toBe('not_found');
    expect(result.rdap_coverage).toBe(true);
    expect(result.domain).toBe('unregistered-domain-xyz.com');
    // No error thrown — RDAP 404 is a data signal
  });

  it('returns available: false with registrar and expiry when domain is registered', async () => {
    rdap.checkAvailability.mockResolvedValue({
      available: false,
      registration_status: 'registered',
      record: registeredRecord,
    });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'taken.com' });
    const result = await whoisCheckAvailability.handler(input, ctx);

    expect(result.available).toBe(false);
    expect(result.rdap_coverage).toBe(true);
    expect(result.registrar).toBe('Big Registrar LLC');
    expect(result.expiry_date).toBe('2026-01-01T00:00:00Z');
  });

  it('returns available: null with rdap_coverage: false for TLD with no RDAP server', async () => {
    rdap.checkAvailability.mockResolvedValue({
      available: null,
      registration_status: 'unknown',
      rdap_coverage: false,
    });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'example.local' });
    const result = await whoisCheckAvailability.handler(input, ctx);

    expect(result.available).toBeNull();
    expect(result.rdap_coverage).toBe(false);
    // No error thrown — no-coverage is returned as data
  });

  it('rejects input without a dot at the schema boundary', () => {
    expect(whoisCheckAvailability.input.safeParse({ domain: 'nodot' }).success).toBe(false);
  });

  it('normalizes domain to lowercase', async () => {
    rdap.checkAvailability.mockResolvedValue({
      available: null,
      registration_status: 'not_found',
      rdap_coverage: true,
    });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'UPPER.COM' });
    const result = await whoisCheckAvailability.handler(input, ctx);
    expect(result.domain).toBe('upper.com');
  });

  it('formats a missing record without implying registration eligibility', () => {
    const output = {
      domain: 'free.com',
      available: null,
      registration_status: 'not_found' as const,
      rdap_coverage: true,
    };
    const blocks = whoisCheckAvailability.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text.split('\n')).toEqual([
      '# Domain: free.com',
      '**Registration Status:** not_found',
      '**Available:** Unknown — RDAP record absence does not establish eligibility',
      '**RDAP Coverage:** Yes',
    ]);
  });

  it('formats registered domain result with registrar and expiry', () => {
    const output = {
      domain: 'taken.com',
      available: false as const,
      registration_status: 'registered' as const,
      rdap_coverage: true,
      registrar: 'Big Registrar LLC',
      expiry_date: '2026-01-01T00:00:00Z',
    };
    const blocks = whoisCheckAvailability.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text.split('\n')).toEqual([
      '# Domain: taken.com',
      '**Registration Status:** registered',
      '**Available:** No — registered',
      '**RDAP Coverage:** Yes',
      '**Registrar:** Big Registrar LLC',
      '**Expires:** 2026-01-01T00:00:00Z',
    ]);
  });

  it('formats no-coverage result as unknown availability', () => {
    const output = {
      domain: 'example.zz',
      available: null,
      registration_status: 'unknown' as const,
      rdap_coverage: false,
    };
    const blocks = whoisCheckAvailability.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text.split('\n')).toEqual([
      '# Domain: example.zz',
      '**Registration Status:** unknown',
      '**Available:** Unknown — RDAP record absence does not establish eligibility',
      '**RDAP Coverage:** No',
    ]);
  });
});
