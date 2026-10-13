/**
 * @fileoverview Service-level tests for RdapService RDAP 404 handling — the
 * upstream "object does not exist" signal must convert to the declared
 * not-found error contracts (or the availability result) without retries.
 * @module tests/services/rdap-service.test
 */

import { createRequire, syncBuiltinESMExports } from 'node:module';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  createFetchMock,
  createMockContext,
  runToolContract,
} from '@cyanheads/mcp-ts-core/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { getServerConfig } from '@/config/server-config.js';
import { whoisCheckAvailability } from '@/mcp-server/tools/definitions/whois-check-availability.tool.js';
import { whoisLookupAsn } from '@/mcp-server/tools/definitions/whois-lookup-asn.tool.js';
import { whoisLookupDomain } from '@/mcp-server/tools/definitions/whois-lookup-domain.tool.js';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import * as rdap from '@/services/rdap/rdap-service.js';
import { RdapService } from '@/services/rdap/rdap-service.js';
import { textOf, upstream } from '../helpers/upstream.js';

const dns: typeof import('node:dns/promises') = createRequire(import.meta.url)('node:dns/promises');

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

  it('reports a 404 as not_found without an eligibility promise', async () => {
    const { http, service } = setup404();
    try {
      const ctx = createMockContext({ errors: whoisLookupDomain.errors });
      await expect(service.checkAvailability('available.com', ctx)).resolves.toEqual({
        available: null,
        registration_status: 'not_found',
        rdap_coverage: true,
      });
    } finally {
      http.restore();
    }
  });
});

describe('IP bootstrap prefix boundaries', () => {
  let http: ReturnType<typeof createFetchMock>;
  afterEach(() => http?.restore());

  it.each([
    ['8.8.8.8', false, '0.0.0.0/0', true],
    ['8.8.8.8', false, '8.8.8.8/32', true],
    ['8.8.8.9', false, '8.8.8.8/32', false],
    ['2001:db8::1', true, '::/0', true],
    ['2001:db8::1', true, '2001:db8::1/128', true],
    ['2001:db8::2', true, '2001:db8::1/128', false],
    ['2001:db8:1:ffff::1', true, '2001:db8:1::/48', true],
    ['2001:db8:2::1', true, '2001:db8:1::/48', false],
  ] as const)('routes %s against %s/%s', async (ip, ipv6, cidr, matches) => {
    http = createFetchMock([
      {
        match: `https://data.iana.org/rdap/${ipv6 ? 'ipv6' : 'ipv4'}.json`,
        respond: Response.json({ services: [[[cidr], [RDAP_BASE]]] }),
      },
    ]);
    http.install();
    expect(await new RdapService().findIpRdapServer(ip, ipv6, createMockContext())).toBe(
      matches ? RDAP_BASE : null,
    );
  });
});

describe('RDAP evidence regressions', () => {
  let http: ReturnType<typeof upstream>;
  afterEach(() => {
    http?.restore();
    vi.restoreAllMocks();
  });

  it('declares missing IP route as terminal NotFound (#15)', async () => {
    http = upstream({ coverage: false });
    const result = await runToolContract(whoisLookupIp, { ip: '224.0.0.1' });
    expect(result.structuredContent).toMatchObject({
      error: {
        code: -32001,
        data: {
          reason: 'ip_no_rdap_route',
          retryable: false,
          recovery: { hint: expect.any(String) },
        },
      },
    });
    expect(textOf(result)).toContain('not retryable');
    expect(http.calls).toHaveLength(1);
  });
  it('keeps bootstrap HTTP failures operational rather than missing-route errors (#15)', async () => {
    http = createFetchMock([
      { match: BOOTSTRAP_IPV4, respond: new Response(null, { status: 503 }) },
    ]);
    http.install();
    vi.spyOn(rdap, 'getRdapService').mockReturnValue(new RdapService());
    const result = await runToolContract(whoisLookupIp, { ip: '224.0.0.1' });
    expect(result.structuredContent).toMatchObject({
      error: { code: -32000, data: { status: 503 } },
    });
    expect(textOf(result)).not.toContain('ip_no_rdap_route');
    expect(http.calls).toHaveLength(1);
  });

  it('returns not_found/null for a registry miss (#18)', async () => {
    http = upstream({ rdap: () => new Response(null, { status: 404 }) });
    const result = await runToolContract(whoisCheckAvailability, { domain: 'missing.com' });
    expect(result.structuredContent).toMatchObject({
      registration_status: 'not_found',
      available: null,
    });
    expect(textOf(result)).not.toContain('Available:** Yes');
  });

  it.each([
    ['www.github.com', 'github.com'],
    ['www.example.co.uk', 'example.co.uk'],
  ])('rejects known subdomain %s (#18)', async (domain, parent) => {
    http = upstream();
    const result = await runToolContract(whoisCheckAvailability, { domain });
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'non_registrable_domain', registrable_parent: parent } },
    });
    expect(textOf(result)).toContain(parent);
    expect(http.calls).toHaveLength(0);
  });

  it('preserves public org alongside redaction evidence in nested registrants (#19/#20)', async () => {
    http = upstream({
      rdap: () =>
        Response.json({
          ldhName: 'example.com',
          entities: [
            {
              entities: [
                {
                  roles: ['registrant'],
                  vcardArray: [
                    'vcard',
                    [
                      ['fn', {}, 'text', 'REDACTED FOR PRIVACY'],
                      ['org', {}, 'text', ['Example Organization', 'Research']],
                    ],
                  ],
                },
              ],
            },
          ],
        }),
    });
    const result = await runToolContract(whoisLookupDomain, { domain: 'example.com' });
    expect(result.structuredContent).toMatchObject({
      registrant_org: 'Example Organization',
      registrant_redacted: true,
      dnssec_signed: null,
    });
    expect(textOf(result)).toContain('Example Organization');
    expect(textOf(result)).toContain('DNSSEC:** Unknown');
  });

  it('does not infer organization/privacy/DNSSEC from missing evidence (#19/#20)', async () => {
    http = upstream();
    const result = await runToolContract(whoisLookupDomain, { domain: 'example.com' });
    expect(result.structuredContent).toMatchObject({
      registrant_redacted: null,
      dnssec_signed: null,
    });
    expect(result.structuredContent).not.toHaveProperty('registrant_org');
    expect(textOf(result)).toContain('Registrant Redacted:** Unknown');
  });
  it.each([
    [
      {
        entities: [
          { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Jane Example']]] },
        ],
      },
      null,
      undefined,
    ],
    [
      {
        entities: [
          {
            roles: ['registrant'],
            vcardArray: ['vcard', [['org', {}, 'text', 'REDACTED FOR PRIVACY']]],
          },
        ],
      },
      true,
      undefined,
    ],
    [{ redacted: [{ name: { type: 'Registry Handle' }, prePath: '$.handle' }] }, null, undefined],
    [{ redacted: [{ name: { type: 'Registrant Email' } }] }, true, undefined],
    [
      {
        entities: [
          {
            roles: ['administrative'],
            remarks: [{ description: ['Contact redacted for privacy'] }],
          },
        ],
      },
      null,
      undefined,
    ],
    [
      {
        entities: [
          {
            entities: [
              {
                roles: ['registrant'],
                remarks: [{ description: ['Contact redacted for privacy'] }],
                vcardArray: ['vcard', [['org', {}, 'text', 'Public Org']]],
              },
            ],
          },
        ],
      },
      true,
      'Public Org',
    ],
  ] as const)(
    'keeps scoped registrant evidence independent of fn and unrelated fields (#19)',
    async (payload, privacy, org) => {
      http = upstream({ rdap: () => Response.json({ ldhName: 'example.com', ...payload }) });
      const result = await runToolContract(whoisLookupDomain, { domain: 'example.com' });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toHaveProperty('registrant_redacted', privacy);
      if (org) expect(result.structuredContent).toHaveProperty('registrant_org', org);
      else expect(result.structuredContent).not.toHaveProperty('registrant_org');
      expect(textOf(result)).toContain(
        privacy === true ? 'Yes (GDPR/privacy)' : 'Registrant Redacted:** Unknown',
      );
    },
  );
  it.each([
    undefined,
    {},
    { zoneSigned: true },
    { delegationSigned: false },
    { delegationSigned: true },
  ])('uses only explicit delegationSigned (#20)', async (secureDNS) => {
    http = upstream({ rdap: () => Response.json({ ldhName: 'example.com', secureDNS }) });
    const result = await runToolContract(whoisLookupDomain, { domain: 'example.com' });
    expect(result.structuredContent).toHaveProperty(
      'dnssec_signed',
      secureDNS?.delegationSigned ?? null,
    );
    expect(textOf(result)).toContain(
      secureDNS?.delegationSigned === undefined
        ? 'DNSSEC:** Unknown'
        : secureDNS.delegationSigned
          ? 'DNSSEC:** Signed'
          : 'DNSSEC:** Not signed',
    );
  });
  it('treats a private suffix as a hosting boundary rather than an ICANN registration boundary (#18)', async () => {
    http = upstream();
    const result = await runToolContract(whoisCheckAvailability, { domain: 'foo.github.io' });
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'non_registrable_domain', registrable_parent: 'github.io' } },
    });
    expect(http.calls).toHaveLength(0);
  });

  it.each([
    [
      { v4prefix: '192.0.2.0', length: 25 },
      { v4prefix: '192.0.2.128', length: 26 },
    ],
    [
      { v6prefix: '2001:db8::', length: 33 },
      { v6prefix: '2001:db8:8000::', length: 33 },
    ],
  ])('preserves every provider CIDR without a misleading scalar (#21)', async (...cidrs) => {
    http = upstream({ rdap: () => Response.json({ cidr0_cidrs: cidrs }) });
    const record = await new RdapService().lookupIp('192.0.2.150', createMockContext());
    expect(record).toHaveProperty(
      'cidrs',
      cidrs.map((cidr) => `${'v4prefix' in cidr ? cidr.v4prefix : cidr.v6prefix}/${cidr.length}`),
    );
    const result = await runToolContract(whoisLookupIp, { ip: '192.0.2.150' });
    const expected = cidrs.map(
      (cidr) => `${'v4prefix' in cidr ? cidr.v4prefix : cidr.v6prefix}/${cidr.length}`,
    );
    expect(result.structuredContent).toMatchObject({ cidrs: expected });
    expect(result.structuredContent).not.toHaveProperty('cidr');
    for (const cidr of expected) expect(textOf(result)).toContain(cidr);
  });
});

describe('optional registrar detail (#25)', () => {
  let http: ReturnType<typeof createFetchMock>;
  let dnsAddresses: string[] = [];
  let dnsPending: Promise<string[]> | undefined;
  beforeAll(() => {
    vi.spyOn(dns, 'resolve4').mockImplementation(() => dnsPending ?? Promise.resolve(dnsAddresses));
    vi.spyOn(dns, 'resolve6').mockResolvedValue([]);
    vi.spyOn(dns, 'lookup').mockImplementation(async () => ({
      address: '93.184.216.34',
      family: 4,
    }));
    syncBuiltinESMExports();
  });
  beforeEach(() => {
    dnsAddresses = [];
    dnsPending = undefined;
    vi.clearAllMocks();
  });
  afterEach(() => {
    http?.restore();
    if (vi.isMockFunction(rdap.getRdapService)) vi.mocked(rdap.getRdapService).mockRestore();
    vi.useRealTimers();
  });
  afterAll(() => {
    vi.restoreAllMocks();
    syncBuiltinESMExports();
  });
  const referral = 'https://8.8.8.8/domain/example.com';
  function registry(
    href = referral,
    response = Response.json({
      objectClassName: 'domain',
      ldhName: 'example.com',
      entities: [
        {
          roles: ['registrant'],
          vcardArray: [
            'vcard',
            [
              ['org', {}, 'text', 'Public Organization'],
              ['fn', {}, 'text', 'REDACTED REGISTRANT'],
            ],
          ],
        },
      ],
    }),
  ) {
    http = createFetchMock([
      { match: BOOTSTRAP_DNS, respond: Response.json({ services: [[['com'], [RDAP_BASE]]] }) },
      {
        match: `${RDAP_BASE}/domain/example.com`,
        respond: Response.json({
          objectClassName: 'domain',
          ldhName: 'example.com',
          status: ['registry-status'],
          links: [{ rel: 'related', type: 'application/rdap+json', href }],
        }),
      },
      { match: referral, respond: response },
    ]);
    http.install();
  }
  it('keeps the default registry-only fast path', async () => {
    registry();
    const service = new RdapService();
    const result = await service.lookupDomain('example.com', createMockContext());
    expect(result).not.toHaveProperty('registrar_detail');
    expect(http.calls).toHaveLength(2);
  });
  it('returns nested registrar contact facts without changing registry authority', async () => {
    registry();
    const service = new RdapService();
    const result = await service.lookupDomain('example.com', createMockContext(), true);
    expect(result).toMatchObject({
      status: ['registry-status'],
      registrant_redacted: null,
      registrar_detail: {
        status: 'found',
        source: referral,
        registrant_org: 'Public Organization',
        registrant_redacted: true,
      },
    });
    expect(http.calls).toHaveLength(3);
  });
  it.each([
    'https://127.0.0.1/domain/example.com',
    'https://[::ffff:127.0.0.1]/domain/example.com',
    'http://8.8.8.8/domain/example.com',
    'https://user:pass@8.8.8.8/domain/example.com',
  ])('rejects unsafe referral %s before any request', async (href) => {
    registry(href);
    const result = await new RdapService().lookupDomain('example.com', createMockContext(), true);
    expect(result).toMatchObject({
      registrar_detail: { status: 'failed', source_error: expect.any(String) },
    });
    expect(http.calls).toHaveLength(2);
  });

  it('returns optional detail and provenance through structured and text surfaces', async () => {
    registry();
    vi.spyOn(rdap, 'getRdapService').mockReturnValue(new RdapService());
    const result = await runToolContract(whoisLookupDomain, {
      domain: 'example.com',
      include_registrar: true,
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      registrar_detail: {
        status: 'found',
        source: referral,
        registrant_org: 'Public Organization',
      },
    });
    expect(textOf(result).split('\n')).toEqual(
      expect.arrayContaining([
        '**Registrar Detail:** found',
        `**Registrar Source:** ${referral}`,
        '**Registrar Registrant Org:** Public Organization',
        '**Registrar Registrant Redacted:** Yes',
      ]),
    );
  });
  it('keeps a registrar DNS-to-private rejection off the network', async () => {
    dnsAddresses = ['192.168.1.2'];
    registry('https://registrar.example/domain/example.com');
    const result = await new RdapService().lookupDomain('example.com', createMockContext(), true);
    expect(dns.resolve4).toHaveBeenCalledWith('registrar.example');
    expect(result.registrar_detail).toMatchObject({
      status: 'failed',
      source_error: expect.stringContaining('non-global'),
    });
    expect(http.calls).toHaveLength(2);
  });
  it.each([
    new Response(null, { status: 503 }),
    Response.json({ objectClassName: 'entity', ldhName: 'example.com' }),
    Response.json({ objectClassName: 'domain', ldhName: 'wrong.com' }),
    new Response('<html>wrong</html>', { headers: { 'content-type': 'text/html' } }),
  ])('retains registry fields on HTTP/content/object/domain failure', async (response) => {
    registry(referral, response);
    const result = await new RdapService().lookupDomain('example.com', createMockContext(), true);
    expect(result).toMatchObject({
      status: ['registry-status'],
      registrar_detail: { status: 'failed', source: referral, source_error: expect.any(String) },
    });
    expect(http.calls).toHaveLength(3);
  });
  it('reports no_referral without extra requests', async () => {
    http = createFetchMock([
      { match: BOOTSTRAP_DNS, respond: Response.json({ services: [[['com'], [RDAP_BASE]]] }) },
      {
        match: `${RDAP_BASE}/domain/example.com`,
        respond: Response.json({ objectClassName: 'domain', ldhName: 'example.com' }),
      },
    ]);
    http.install();
    expect(
      (await new RdapService().lookupDomain('example.com', createMockContext(), true))
        .registrar_detail,
    ).toEqual({ status: 'no_referral' });
    expect(http.calls).toHaveLength(2);
  });
  it('rejects a private redirect before fetching its destination', async () => {
    registry(
      referral,
      new Response(null, {
        status: 302,
        headers: { location: 'https://10.0.0.1/domain/example.com' },
      }),
    );
    const result = await new RdapService().lookupDomain('example.com', createMockContext(), true);
    expect(result.registrar_detail).toMatchObject({ status: 'failed' });
    expect(http.calls).toHaveLength(3);
  });
  it('caps redirect loops at five transitions without retrying', async () => {
    registry(referral, new Response(null, { status: 302, headers: { location: referral } }));
    const result = await new RdapService().lookupDomain('example.com', createMockContext(), true);
    expect(result.registrar_detail).toMatchObject({
      status: 'failed',
      source_error: expect.stringContaining('redirect'),
    });
    expect(http.calls).toHaveLength(8);
  });
  it('propagates cancellation without starting optional work', async () => {
    const controller = new AbortController();
    registry();
    vi.spyOn(rdap, 'getRdapService').mockReturnValue(new RdapService());
    controller.abort();
    const result = await runToolContract(
      whoisLookupDomain,
      { domain: 'example.com', include_registrar: true },
      { context: { signal: controller.signal } },
    );
    expect(result.structuredContent).toMatchObject({ error: { code: -32011 } });
    expect(http.calls).toHaveLength(0);
  });
  it('propagates caller abort during the registrar request', async () => {
    const controller = new AbortController();
    registry();
    http.restore();
    http = createFetchMock([
      { match: BOOTSTRAP_DNS, respond: Response.json({ services: [[['com'], [RDAP_BASE]]] }) },
      {
        match: `${RDAP_BASE}/domain/example.com`,
        respond: Response.json({
          ldhName: 'example.com',
          links: [{ rel: 'related', type: 'application/rdap+json', href: referral }],
        }),
      },
      {
        match: referral,
        respond: () => {
          controller.abort();
          return Response.json({ objectClassName: 'domain', ldhName: 'example.com' });
        },
      },
    ]);
    http.install();
    vi.spyOn(rdap, 'getRdapService').mockReturnValue(new RdapService());
    const result = await runToolContract(
      whoisLookupDomain,
      { domain: 'example.com', include_registrar: true },
      { context: { signal: controller.signal } },
    );
    expect(result.structuredContent).toMatchObject({ error: { code: -32011 } });
    expect(http.calls).toHaveLength(3);
  });
  it('enforces one deadline across redirect responses and a stalled final body', async () => {
    vi.useFakeTimers();
    let bodyEntered = false;
    let bodyAborted = false;
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
      const controller = new AbortController();
      setTimeout(
        () =>
          controller.abort(new DOMException('Total registrar deadline exceeded', 'TimeoutError')),
        ms,
      );
      return controller.signal;
    });
    http = createFetchMock([
      { match: BOOTSTRAP_DNS, respond: Response.json({ services: [[['com'], [RDAP_BASE]]] }) },
      {
        match: `${RDAP_BASE}/domain/example.com`,
        respond: Response.json({
          ldhName: 'example.com',
          status: ['registry-status'],
          links: [{ rel: 'related', type: 'application/rdap+json', href: referral }],
        }),
      },
      {
        match: referral,
        respond: () =>
          new Promise((resolve) =>
            setTimeout(
              () =>
                resolve(
                  new Response(null, {
                    status: 302,
                    headers: { location: 'https://8.8.8.8/final' },
                  }),
                ),
              getServerConfig().rdapTimeoutMs / 2,
            ),
          ),
      },
      {
        match: 'https://8.8.8.8/final',
        respond: (request) =>
          new Response(
            new ReadableStream(
              {
                pull(controller) {
                  bodyEntered = true;
                  return new Promise<void>((resolve) => {
                    request.signal.addEventListener(
                      'abort',
                      () => {
                        bodyAborted = true;
                        controller.error(request.signal.reason);
                        resolve();
                      },
                      { once: true },
                    );
                  });
                },
              },
              { highWaterMark: 0 },
            ),
            { headers: { 'content-type': 'application/rdap+json' } },
          ),
      },
    ]);
    http.install();
    let settled = false;
    const pending = new RdapService()
      .lookupDomain('example.com', createMockContext(), true)
      .then((record) => {
        settled = true;
        return record;
      });
    try {
      await vi.advanceTimersByTimeAsync(getServerConfig().rdapTimeoutMs / 2);
      expect(bodyEntered).toBe(true);
      expect(bodyAborted).toBe(false);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(getServerConfig().rdapTimeoutMs / 2);
      expect(bodyAborted).toBe(true);
      expect(settled).toBe(true);
      expect(await pending).toMatchObject({
        status: ['registry-status'],
        registrar_detail: {
          status: 'failed',
          source_error: expect.stringMatching(/deadline|timeout|timed out/i),
        },
      });
      expect(http.calls.map((call) => call.request.url)).toEqual([
        BOOTSTRAP_DNS,
        `${RDAP_BASE}/domain/example.com`,
        referral,
        'https://8.8.8.8/final',
      ]);
    } finally {
      await vi.runAllTimersAsync();
      await pending;
      vi.mocked(AbortSignal.timeout).mockRestore();
    }
  });
  it('settles a stalled DNS preflight by the deadline and dispatches no late request', async () => {
    vi.useFakeTimers();
    const deferred = Promise.withResolvers<string[]>();
    dnsPending = deferred.promise;
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
      const controller = new AbortController();
      setTimeout(
        () =>
          controller.abort(new DOMException('Total registrar deadline exceeded', 'TimeoutError')),
        ms,
      );
      return controller.signal;
    });
    registry('https://registrar.example/domain/example.com');
    const nativeSemanticsFetch = globalThis.fetch;
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (init?.signal?.aborted) return Promise.reject(init.signal.reason);
      return nativeSemanticsFetch(input, init);
    });
    let settled = false;
    const pending = new RdapService()
      .lookupDomain('example.com', createMockContext(), true)
      .then((record) => {
        settled = true;
        return record;
      });
    try {
      await vi.advanceTimersByTimeAsync(getServerConfig().rdapTimeoutMs);
      expect(settled).toBe(true);
      expect(await pending).toMatchObject({
        registrar_detail: { status: 'failed', source_error: expect.stringMatching(/deadline/i) },
      });
    } finally {
      deferred.resolve(['93.184.216.34']);
      await vi.advanceTimersByTimeAsync(1);
      await pending;
      expect(http.calls).toHaveLength(2);
      vi.mocked(globalThis.fetch).mockRestore();
      vi.mocked(AbortSignal.timeout).mockRestore();
    }
  });
});
