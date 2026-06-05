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

  // CRITICAL: RDAP 404 → available: true — this is DATA, not an error
  it('returns available: true when RDAP 404 (domain not registered)', async () => {
    rdap.checkAvailability.mockResolvedValue({ available: true });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'unregistered-domain-xyz.com' });
    const result = await whoisCheckAvailability.handler(input, ctx);

    expect(result.available).toBe(true);
    expect(result.rdap_coverage).toBe(true);
    expect(result.domain).toBe('unregistered-domain-xyz.com');
    // No error thrown — RDAP 404 is a data signal
  });

  it('returns available: false with registrar and expiry when domain is registered', async () => {
    rdap.checkAvailability.mockResolvedValue({ available: false, record: registeredRecord });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'taken.com' });
    const result = await whoisCheckAvailability.handler(input, ctx);

    expect(result.available).toBe(false);
    expect(result.rdap_coverage).toBe(true);
    expect(result.registrar).toBe('Big Registrar LLC');
    expect(result.expiry_date).toBe('2026-01-01T00:00:00Z');
  });

  it('returns available: null with rdap_coverage: false for TLD with no RDAP server', async () => {
    rdap.checkAvailability.mockResolvedValue({ available: null, rdap_coverage: false });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'example.local' });
    const result = await whoisCheckAvailability.handler(input, ctx);

    expect(result.available).toBeNull();
    expect(result.rdap_coverage).toBe(false);
    // No error thrown — no-coverage is returned as data
  });

  it('throws invalid_domain for input without a dot', async () => {
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'nodot' });
    await expect(whoisCheckAvailability.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_domain' },
    });
  });

  it('normalizes domain to lowercase', async () => {
    rdap.checkAvailability.mockResolvedValue({ available: true });
    const ctx = createMockContext({ errors: whoisCheckAvailability.errors });
    const input = whoisCheckAvailability.input.parse({ domain: 'UPPER.COM' });
    const result = await whoisCheckAvailability.handler(input, ctx);
    expect(result.domain).toBe('upper.com');
  });

  it('formats available domain result', () => {
    const output = { domain: 'free.com', available: true as const, rdap_coverage: true };
    const blocks = whoisCheckAvailability.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('free.com');
    expect(text).toContain('Yes');
  });

  it('formats registered domain result with registrar and expiry', () => {
    const output = {
      domain: 'taken.com',
      available: false as const,
      rdap_coverage: true,
      registrar: 'Big Registrar LLC',
      expiry_date: '2026-01-01T00:00:00Z',
    };
    const blocks = whoisCheckAvailability.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('taken.com');
    expect(text).toContain('No');
    expect(text).toContain('Big Registrar LLC');
    expect(text).toContain('2026-01-01T00:00:00Z');
  });

  it('formats no-coverage result as unknown availability', () => {
    const output = { domain: 'example.zz', available: null, rdap_coverage: false };
    const blocks = whoisCheckAvailability.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Unknown');
    expect(text).toContain('No');
  });
});
