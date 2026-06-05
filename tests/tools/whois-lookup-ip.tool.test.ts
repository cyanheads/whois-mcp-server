/**
 * @fileoverview Tests for whois_lookup_ip tool.
 * @module tests/tools/whois-lookup-ip.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import type { NormalizedIpNetwork } from '@/services/rdap/types.js';

// --- service mocks ----------------------------------------------------------

vi.mock('@/services/rdap/rdap-service.js', () => {
  const mockService = {
    lookupIp: vi.fn(),
  };
  return {
    getRdapService: () => mockService,
    // Also re-export the real pure utilities used by the handler
    validateIp: (ip: string) => {
      const parts = ip.split('/');
      const base = parts[0] ?? '';
      const hasCidr = parts.length === 2;
      const isIpv6 = base.includes(':');
      // Very simplified: just check for dots for IPv4 and colons for IPv6
      const valid = isIpv6 ? base.includes(':') : /^\d{1,3}(\.\d{1,3}){3}$/.test(base);
      return { valid, isIpv6, hasCidr };
    },
    ipv4ToPtr: (ip: string) => `${ip.split('.').reverse().join('.')}.in-addr.arpa`,
    ipv6ToPtr: (_ip: string) => 'reversed.ip6.arpa',
    __mockService: mockService,
  };
});

vi.mock('@/services/doh/doh-service.js', () => {
  const mockService = {
    ptrLookup: vi.fn(),
  };
  return {
    getDohService: () => mockService,
    __mockService: mockService,
  };
});

async function getRdapMock() {
  const mod = await import('@/services/rdap/rdap-service.js');
  return (mod as unknown as { __mockService: { lookupIp: ReturnType<typeof vi.fn> } })
    .__mockService;
}

async function getDohMock() {
  const mod = await import('@/services/doh/doh-service.js');
  return (mod as unknown as { __mockService: { ptrLookup: ReturnType<typeof vi.fn> } })
    .__mockService;
}

// --- fixtures ---------------------------------------------------------------

const ipRecord: NormalizedIpNetwork = {
  ip: '8.8.8.8',
  handle: 'NET-8-8-8-0-1',
  start_address: '8.8.8.0',
  end_address: '8.8.8.255',
  cidr: '8.8.8.0/24',
  ip_version: 'v4',
  name: 'LVLT-GOGL-8-8-8',
  type: 'DIRECT ALLOCATION',
  country: 'US',
  org_name: 'Google LLC',
  abuse_email: 'network-abuse@google.com',
  rdap_source: 'ARIN',
  ptr: null,
};

// --- tests ------------------------------------------------------------------

describe('whoisLookupIp', () => {
  let rdap: { lookupIp: ReturnType<typeof vi.fn> };
  let doh: { ptrLookup: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    rdap = await getRdapMock();
    doh = await getDohMock();
    vi.clearAllMocks();
  });

  it('returns IP netblock record with PTR for a public IPv4 address', async () => {
    rdap.lookupIp.mockResolvedValue(ipRecord);
    doh.ptrLookup.mockResolvedValue('dns.google');
    const ctx = createMockContext({ errors: whoisLookupIp.errors });
    const input = whoisLookupIp.input.parse({ ip: '8.8.8.8' });
    const result = await whoisLookupIp.handler(input, ctx);

    expect(result.ip).toBe('8.8.8.8');
    expect(result.org_name).toBe('Google LLC');
    expect(result.cidr).toBe('8.8.8.0/24');
    expect(result.rdap_source).toBe('ARIN');
    expect(result.ptr).toBe('dns.google');
  });

  it('returns ptr: null when PTR lookup fails (best-effort)', async () => {
    rdap.lookupIp.mockResolvedValue(ipRecord);
    doh.ptrLookup.mockResolvedValue(null);
    const ctx = createMockContext({ errors: whoisLookupIp.errors });
    const input = whoisLookupIp.input.parse({ ip: '8.8.8.8' });
    const result = await whoisLookupIp.handler(input, ctx);

    expect(result.ptr).toBeNull();
  });

  // CRITICAL: private/RFC1918 IPs → validation error BEFORE RDAP is called
  it('throws invalid_ip (not private_range) for an invalid IP string', async () => {
    const ctx = createMockContext({ errors: whoisLookupIp.errors });
    const input = whoisLookupIp.input.parse({ ip: 'not-an-ip' });
    await expect(whoisLookupIp.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_ip' },
    });
    expect(rdap.lookupIp).not.toHaveBeenCalled();
  });

  it('propagates private_range error thrown by the RDAP service', async () => {
    const { McpError, JsonRpcErrorCode } = await import('@cyanheads/mcp-ts-core/errors');
    const privateErr = new McpError(JsonRpcErrorCode.InvalidParams, 'private range', {
      reason: 'private_range',
    });
    rdap.lookupIp.mockRejectedValue(privateErr);
    const ctx = createMockContext({ errors: whoisLookupIp.errors });
    const input = whoisLookupIp.input.parse({ ip: '192.168.1.1' });
    await expect(whoisLookupIp.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'private_range' },
    });
  });

  it('handles sparse upstream IP record (only required fields)', async () => {
    const sparse: NormalizedIpNetwork = { ip: '1.1.1.1', ptr: null };
    rdap.lookupIp.mockResolvedValue(sparse);
    doh.ptrLookup.mockResolvedValue(null);
    const ctx = createMockContext({ errors: whoisLookupIp.errors });
    const input = whoisLookupIp.input.parse({ ip: '1.1.1.1' });
    const result = await whoisLookupIp.handler(input, ctx);

    expect(result.ip).toBe('1.1.1.1');
    expect(result.org_name).toBeUndefined();
    expect(result.cidr).toBeUndefined();
    expect(result.ptr).toBeNull();
  });

  it('formats IP result with all key fields', () => {
    const output = { ...ipRecord, ptr: 'dns.google' };
    const blocks = whoisLookupIp.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('8.8.8.8');
    expect(text).toContain('Google LLC');
    expect(text).toContain('8.8.8.0/24');
    expect(text).toContain('ARIN');
    expect(text).toContain('dns.google');
    expect(text).toContain('network-abuse@google.com');
  });

  it('formats ptr: null as Not available', () => {
    const output = { ...ipRecord, ptr: null };
    const blocks = whoisLookupIp.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Not available');
  });
});
