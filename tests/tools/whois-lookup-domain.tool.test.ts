/**
 * @fileoverview Tests for whois_lookup_domain tool.
 * @module tests/tools/whois-lookup-domain.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupDomain } from '@/mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import type { NormalizedDomain } from '@/services/rdap/types.js';

// --- service mock -----------------------------------------------------------

vi.mock('@/services/rdap/rdap-service.js', () => {
  const mockService = {
    lookupDomain: vi.fn(),
  };
  return {
    getRdapService: () => mockService,
    __mockService: mockService,
  };
});

async function getRdapMock() {
  const mod = await import('@/services/rdap/rdap-service.js');
  return (mod as unknown as { __mockService: { lookupDomain: ReturnType<typeof vi.fn> } })
    .__mockService;
}

// --- fixtures ---------------------------------------------------------------

const registeredDomain: NormalizedDomain = {
  domain: 'example.com',
  rdap_coverage: true,
  handle: 'EXAMPLE-HANDLE',
  registrar: 'Example Registrar, Inc.',
  registrar_iana_id: '999',
  created_date: '2000-01-01T00:00:00Z',
  updated_date: '2023-06-01T00:00:00Z',
  expiry_date: '2025-01-01T00:00:00Z',
  rdap_last_updated: '2024-12-01T00:00:00Z',
  status: ['clientTransferProhibited', 'serverDeleteProhibited'],
  nameservers: ['ns1.example.com', 'ns2.example.com'],
  dnssec_signed: false,
  registrant_redacted: true,
};

const noCoverageDomain: NormalizedDomain = {
  domain: 'example.zz',
  rdap_coverage: false,
  status: [],
  nameservers: [],
  dnssec_signed: false,
  registrant_redacted: false,
};

// --- tests ------------------------------------------------------------------

describe('whoisLookupDomain', () => {
  let rdap: { lookupDomain: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    rdap = await getRdapMock();
    vi.clearAllMocks();
  });

  it('returns normalized registration record for a registered domain', async () => {
    rdap.lookupDomain.mockResolvedValue(registeredDomain);
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    const input = whoisLookupDomain.input.parse({ domain: 'example.com' });
    const result = await whoisLookupDomain.handler(input, ctx);

    expect(result.domain).toBe('example.com');
    expect(result.rdap_coverage).toBe(true);
    expect(result.registrar).toBe('Example Registrar, Inc.');
    expect(result.created_date).toBe('2000-01-01T00:00:00Z');
    expect(result.expiry_date).toBe('2025-01-01T00:00:00Z');
    expect(result.status).toContain('clientTransferProhibited');
    expect(result.nameservers).toEqual(['ns1.example.com', 'ns2.example.com']);
    expect(result.dnssec_signed).toBe(false);
    expect(result.registrant_redacted).toBe(true);
  });

  it('throws invalid_domain for a bare hostname without TLD', async () => {
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    const input = whoisLookupDomain.input.parse({ domain: 'notadomain' });
    await expect(whoisLookupDomain.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_domain' },
    });
  });

  it('throws invalid_domain for an empty string', async () => {
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    const input = whoisLookupDomain.input.parse({ domain: '' });
    await expect(whoisLookupDomain.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_domain' },
    });
  });

  it('throws rdap_no_coverage when service returns rdap_coverage: false', async () => {
    rdap.lookupDomain.mockResolvedValue(noCoverageDomain);
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    const input = whoisLookupDomain.input.parse({ domain: 'example.zz' });
    await expect(whoisLookupDomain.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'rdap_no_coverage' },
    });
  });

  it('handles a domain with sparse upstream data (optional fields absent)', async () => {
    const sparse: NormalizedDomain = {
      domain: 'sparse.com',
      rdap_coverage: true,
      status: [],
      nameservers: [],
      dnssec_signed: false,
      registrant_redacted: true,
      // registrar, dates, handle all absent
    };
    rdap.lookupDomain.mockResolvedValue(sparse);
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    const input = whoisLookupDomain.input.parse({ domain: 'sparse.com' });
    const result = await whoisLookupDomain.handler(input, ctx);

    expect(result.rdap_coverage).toBe(true);
    expect(result.registrar).toBeUndefined();
    expect(result.created_date).toBeUndefined();
    expect(result.expiry_date).toBeUndefined();
    expect(result.nameservers).toEqual([]);
    expect(result.status).toEqual([]);
  });

  it('formats output with all key fields present', () => {
    const blocks = whoisLookupDomain.format!(registeredDomain);
    expect(blocks.some((b) => b.type === 'text')).toBe(true);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('example.com');
    expect(text).toContain('Example Registrar, Inc.');
    expect(text).toContain('2025-01-01T00:00:00Z');
    expect(text).toContain('clientTransferProhibited');
    expect(text).toContain('ns1.example.com');
    expect(text).toContain('GDPR');
  });

  it('formats no-coverage result without registration data', () => {
    const blocks = whoisLookupDomain.format!(noCoverageDomain);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('example.zz');
    expect(text).toContain('No');
  });

  // CRITICAL: RDAP 404 on lookupDomain must propagate as domain_not_found, not a generic error
  it('propagates domain_not_found when service throws typed McpError with that reason', async () => {
    const { McpError, JsonRpcErrorCode } = await import('@cyanheads/mcp-ts-core/errors');
    const notFoundErr = new McpError(JsonRpcErrorCode.NotFound, 'Domain not registered', {
      reason: 'domain_not_found',
      domain: 'example.com',
    });
    rdap.lookupDomain.mockRejectedValue(notFoundErr);
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    const input = whoisLookupDomain.input.parse({ domain: 'example.com' });
    await expect(whoisLookupDomain.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'domain_not_found' },
    });
  });

  // CRITICAL: domain_not_found must include recovery.hint so agents can act on it
  it('includes recovery.hint in domain_not_found error', async () => {
    const { McpError, JsonRpcErrorCode } = await import('@cyanheads/mcp-ts-core/errors');
    const notFoundErr = new McpError(
      JsonRpcErrorCode.NotFound,
      'Domain "example.com" is not registered (RDAP 404).',
      {
        reason: 'domain_not_found',
        domain: 'example.com',
      },
    );
    rdap.lookupDomain.mockRejectedValue(notFoundErr);
    const ctx = createMockContext({ errors: whoisLookupDomain.errors });
    const input = whoisLookupDomain.input.parse({ domain: 'example.com' });
    try {
      await whoisLookupDomain.handler(input, ctx);
      throw new Error('expected rejection');
    } catch (err: unknown) {
      const mcpErr = err as { data?: { recovery?: { hint?: string }; reason?: string } };
      expect(mcpErr.data?.reason).toBe('domain_not_found');
      expect(mcpErr.data?.recovery?.hint).toBeTruthy();
      expect(typeof mcpErr.data?.recovery?.hint).toBe('string');
    }
  });
});
