/**
 * @fileoverview Primary RDAP identity and failure contracts at the HTTP boundary.
 * @module tests/tools/primary-domain-contracts.test
 */
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisCheckAvailability } from '@/mcp-server/tools/definitions/whois-check-availability.tool.js';
import { whoisGetDossier } from '@/mcp-server/tools/definitions/whois-get-dossier.tool.js';
import { whoisLookupDomain } from '@/mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
});

describe('primary domain characterization', () => {
  it.each([
    null,
    [],
    'domain',
    42,
    {},
    { errorCode: 503, ldhName: 'example.com' },
    { objectClassName: 'autnum', ldhName: 'example.com' },
    { objectClassName: null, ldhName: 'example.com' },
    { ldhName: 'different.com' },
    { ldhName: 123 },
    { ldhName: 'example.com', unicodeName: 'different.com' },
  ])('rejects invalid source %j on every domain surface', async (raw) => {
    http = upstream({ rdap: () => Response.json(raw) });
    for (const definition of [whoisLookupDomain, whoisCheckAvailability]) {
      const result = await runToolContract(definition, { domain: 'example.com' });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: {
          code: -32000,
          data: {
            reason: 'rdap_invalid_domain_response',
            retryable: false,
            recovery: { hint: expect.any(String) },
          },
        },
      });
      expect(textOf(result)).toContain('Recovery:');
    }
    const dossier = await runToolContract(whoisGetDossier, { domain: 'example.com' });
    expect(dossier.isError).not.toBe(true);
    expect(dossier.structuredContent).toMatchObject({
      registered: null,
      rdap_coverage: null,
      rdap_source_error: expect.any(String),
      dns_nxdomain: false,
    });
    expect(textOf(dossier)).toContain('**RDAP:** Failed');
    expect(
      http.calls.filter((call) => new URL(call.request.url).hostname === 'rdap.test'),
    ).toHaveLength(3);
  });

  it('accepts equivalent IDNA identities without changing the provider name', async () => {
    http = upstream({
      rdap: () => Response.json({ ldhName: 'XN--BCHER-KVA.COM', unicodeName: 'bücher.com' }),
    });
    const result = await runToolContract(whoisLookupDomain, { domain: 'xn--bcher-kva.com' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ domain: 'xn--bcher-kva.com' });
  });
  it.each([
    { ldhName: 'EXAMPLE.COM' },
    { unicodeName: 'example.com' },
    { objectClassName: 'domain', ldhName: 'example.com' },
  ])('accepts sparse matching identity %j', async (raw) => {
    http = upstream({ rdap: () => Response.json(raw) });
    const result = await runToolContract(whoisLookupDomain, { domain: 'example.com' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      domain: 'example.com',
      dnssec_signed: null,
      registrant_redacted: null,
    });
    expect(textOf(result)).toContain('example.com');
  });
});
