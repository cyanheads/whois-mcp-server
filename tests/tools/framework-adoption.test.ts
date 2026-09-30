/**
 * @fileoverview Caller-visible RDAP behavior across framework upgrades.
 * @module tests/tools/framework-adoption.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createFetchMock, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupDomain } from '@/mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import * as rdap from '@/services/rdap/rdap-service.js';

describe('framework recovery and formatting', () => {
  let http: ReturnType<typeof createFetchMock> | undefined;

  afterEach(() => {
    http?.restore();
    vi.restoreAllMocks();
  });

  function upstream(response: Response) {
    vi.spyOn(rdap, 'getRdapService').mockReturnValue(new rdap.RdapService());
    http = createFetchMock([
      {
        match: 'https://data.iana.org/rdap/dns.json',
        respond: Response.json({ services: [[['com'], ['https://rdap.test']]] }),
      },
      { match: 'https://rdap.test/domain/example.com', respond: response },
    ]);
    http.install();
    return http;
  }

  it('preserves domain_not_found recovery on both error surfaces without retrying 404', async () => {
    const requests = upstream(new Response(null, { status: 404 }));
    const result = await runToolContract(whoisLookupDomain, { domain: 'example.com' });
    const hint =
      'The domain is not registered. Use whois_check_availability to confirm availability for registration.';

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.NotFound,
        data: { reason: 'domain_not_found', domain: 'example.com', recovery: { hint } },
      },
    });
    expect(result.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'text', text: expect.stringContaining(hint) }),
      ]),
    );
    expect(requests.calls).toHaveLength(2);
  });

  it('preserves normalized domain data in structured content and formatted text', async () => {
    upstream(
      Response.json({
        ldhName: 'EXAMPLE.COM',
        handle: 'EXAMPLE-HANDLE',
        status: ['active'],
        nameservers: [{ ldhName: 'NS1.EXAMPLE.COM' }],
        secureDNS: { delegationSigned: true },
      }),
    );
    const result = await runToolContract(whoisLookupDomain, { domain: 'EXAMPLE.COM' });

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      domain: 'example.com',
      handle: 'EXAMPLE-HANDLE',
      status: ['active'],
      nameservers: ['ns1.example.com'],
      dnssec_signed: true,
    });
    const text = result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
    for (const value of ['example.com', 'EXAMPLE-HANDLE', 'active', 'ns1.example.com', 'Signed']) {
      expect(text).toContain(value);
    }
  });

  it('preserves declared validation recovery on both error surfaces', async () => {
    const result = await runToolContract(whoisLookupDomain, { domain: 'invalid' });
    const hint =
      'Provide a valid fully-qualified domain name like "example.com" or "sub.example.org".';
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: { reason: 'invalid_domain', recovery: { hint } },
      },
    });
    expect(result.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'text', text: expect.stringContaining(hint) }),
      ]),
    );
  });
});
