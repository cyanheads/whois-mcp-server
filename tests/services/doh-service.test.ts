/**
 * @fileoverview Real DoH routing, fallback, and query provenance contracts.
 * @module tests/services/doh-service.test
 */

import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getServerConfig } from '@/config/server-config.js';
import { whoisGetDns } from '@/mcp-server/tools/definitions/whois-get-dns.tool.js';
import { DohService } from '@/services/doh/doh-service.js';
import type { DnsRecordType } from '@/services/doh/types.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('DoH characterization', () => {
  it('retains the supported NXDOMAIN answer chain and provenance (#29)', async () => {
    const answers = [
      { type: 5, name: 'example.com.', TTL: 60, data: 'second.example.' },
      { type: 5, name: 'second.example.', TTL: 30, data: 'absent.example.' },
      { type: 999, name: 'example.com.', TTL: 1, data: 'unsupported' },
    ];
    http = upstream({ dns: () => Response.json({ Status: 3, TC: false, Answer: answers }) });
    const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: ['A'] });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      nxdomain: true,
      records: answers
        .slice(0, 2)
        .map(({ name, TTL, data }) => ({ type: 'CNAME', name, ttl: TTL, data })),
      query_sources: [{ type: 'A', source: 'cloudflare' }],
    });
    for (const answer of answers.slice(0, 2)) {
      expect(textOf(result)).toContain(answer.name);
      expect(textOf(result)).toContain(answer.data);
      expect(textOf(result)).toContain(`TTL: ${answer.TTL}s`);
    }
    expect(textOf(result)).toContain('A: cloudflare');
  });
  it('keeps PTR NXDOMAIN terminal even when an alias is present (#29)', async () => {
    http = upstream({
      dns: () =>
        Response.json({
          Status: 3,
          Answer: [{ type: 5, name: '1.2.0.192.in-addr.arpa.', TTL: 60, data: 'absent.example.' }],
        }),
    });
    expect(await new DohService().ptrLookup('1.2.0.192.in-addr.arpa', createMockContext())).toEqual(
      { ptr: null, ptr_status: 'not_found' },
    );
    expect(http.calls).toHaveLength(1);
  });
  it('keeps one total deadline across successive PTR aliases (#22)', async () => {
    vi.useFakeTimers();
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
      const controller = new AbortController();
      setTimeout(
        () => controller.abort(new DOMException('Total deadline exceeded', 'TimeoutError')),
        ms,
      );
      return controller.signal;
    });
    let calls = 0;
    const httpBoundary = await import('@cyanheads/mcp-ts-core/testing');
    const original = httpBoundary.createFetchMock([
      {
        match: (request) => new URL(request.url).hostname === 'cloudflare-dns.com',
        respond: (request) =>
          new Promise<Response>((resolve, reject) => {
            calls++;
            const timer = setTimeout(
              () =>
                resolve(
                  Response.json({
                    Status: 0,
                    Answer: [
                      {
                        type: 5,
                        name: new URL(request.url).searchParams.get('name'),
                        TTL: 60,
                        data: `${calls}.alias.example.`,
                      },
                    ],
                  }),
                ),
              getServerConfig().dohTimeoutMs / 2,
            );
            request.signal.addEventListener(
              'abort',
              () => {
                clearTimeout(timer);
                reject(request.signal.reason);
              },
              { once: true },
            );
          }),
      },
    ]);
    original.install();
    try {
      const pending = new DohService().ptrLookup('1.2.0.192.in-addr.arpa', createMockContext());
      await vi.advanceTimersByTimeAsync(getServerConfig().dohTimeoutMs);
      expect(await pending).toMatchObject({
        ptr: null,
        ptr_status: 'failed',
        ptr_source_error: expect.stringMatching(/deadline|timeout/i),
      });
      expect(calls).toBe(2);
      expect(original.calls).toHaveLength(2);
    } finally {
      original.restore();
    }
  });
  it.each(['found', 'loop', 'limit'] as const)(
    'walks several alias-only replies to %s (#22)',
    async (outcome) => {
      http = upstream({
        dns: (_type, url) => {
          const owner = url.searchParams.get('name')!;
          const hop = owner === '1.2.0.192.in-addr.arpa' ? 0 : Number(owner.split('.')[0]);
          const found = outcome === 'found' && hop === 3;
          return Response.json({
            Status: 0,
            Answer: [
              {
                type: found ? 12 : 5,
                name: `${owner.toUpperCase()}.`,
                TTL: 60,
                data: found
                  ? 'ACTUAL.EXAMPLE.'
                  : outcome === 'loop' && hop === 2
                    ? '1.alias.example.'
                    : `${hop + 1}.alias.example.`,
              },
            ],
          });
        },
      });
      const result = await new DohService().ptrLookup(
        '1.2.0.192.in-addr.arpa',
        createMockContext(),
      );
      expect(result).toMatchObject({
        ptr: outcome === 'found' ? 'actual.example' : null,
        ptr_status: outcome === 'found' ? 'found' : 'failed',
      });
      expect(http.calls).toHaveLength(outcome === 'found' ? 4 : outcome === 'loop' ? 3 : 6);
      if (result.ptr_status === 'failed') expect(result.ptr_source_error).toContain('limit');
    },
  );
  it('ignores unrelated aliases and PTR owners (#22)', async () => {
    http = upstream({
      dns: () =>
        Response.json({
          Status: 0,
          Answer: [
            { type: 5, name: 'unrelated.example.', TTL: 60, data: 'private.example.' },
            { type: 12, name: 'unrelated.example.', TTL: 60, data: 'wrong.example.' },
          ],
        }),
    });
    expect(await new DohService().ptrLookup('1.2.0.192.in-addr.arpa', createMockContext())).toEqual(
      { ptr: null, ptr_status: 'not_found' },
    );
    expect(http.calls).toHaveLength(1);
  });
  it('stops retries and fallback after caller abort (#16/#22)', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const started = Promise.withResolvers<void>();
    http = upstream({
      dns: () => {
        started.resolve();
        return new Response(null, { status: 503 });
      },
    });
    const pending = runToolContract(
      whoisGetDns,
      { domain: 'example.com', types: ['A'] },
      { context: { signal: controller.signal } },
    );
    await started.promise;
    controller.abort();
    await vi.runAllTimersAsync();
    const result = await pending;
    expect(result.structuredContent).toMatchObject({ error: { code: -32011 } });
    expect(http.calls).toHaveLength(1);
    expect(textOf(result)).toMatch(/abort|cancel/i);
  });
  it('does not turn an aborted PTR call into partial success (#22)', async () => {
    const controller = new AbortController();
    http = upstream({
      dns: () => {
        controller.abort();
        return Response.json({ Status: 0 });
      },
    });
    await expect(
      new DohService().ptrLookup(
        '1.2.0.192.in-addr.arpa',
        createMockContext({ signal: controller.signal }),
      ),
    ).rejects.toThrow();
    expect(http.calls).toHaveLength(1);
  });
  it.each(['_dmarc.github.com', '_netblocks.google.com', 'github.com.'])(
    'accepts DNS owner %s (#17)',
    async (domain) => {
      http = upstream();
      const result = await runToolContract(whoisGetDns, { domain, types: ['TXT'] });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ domain: domain.replace(/\.$/, '') });
      expect(new URL(http.calls[0]!.request.url).searchParams.get('name')).toBe(
        domain.replace(/\.$/, ''),
      );
    },
  );

  it('renders each complete TXT literal in a sized fence (#23)', async () => {
    const values = [
      '',
      '  literal ` <tag> **bold** [link](https://example.com) | \\  ',
      '```\nend',
      'duplicate',
      'duplicate',
    ];
    http = upstream({
      dns: () =>
        Response.json({
          Status: 0,
          Answer: values.map((data) => ({ type: 16, name: 'example.com.', TTL: 60, data })),
        }),
    });
    const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: ['TXT'] });
    const literals = [...textOf(result).matchAll(/^(`{3,})\n([\s\S]*?)\n\1$/gm)].map(
      (match) => match[2],
    );
    expect(literals).toEqual(values);
    expect(result.structuredContent).toMatchObject({ records: values.map((data) => ({ data })) });
    expect(textOf(result)).toContain('TTL: 60s');
  });

  it.each([2, 5])('rejects exhausted DNS status %s with recovery (#16)', async (Status) => {
    vi.useFakeTimers();
    http = upstream({ dns: () => Response.json({ Status }) });
    const pending = runToolContract(whoisGetDns, { domain: 'example.com', types: ['A'] });
    await vi.runAllTimersAsync();
    const result = await pending;
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        data: {
          reason: 'dns_response_failed',
          type: 'A',
          resolver: 'nextdns',
          status: Status,
          recovery: { hint: expect.any(String) },
        },
      },
    });
    expect(textOf(result)).toContain('dns_response_failed');
    expect(textOf(result)).toContain('Recovery:');
  });

  it('rejects truncated answers rather than consuming them (#16)', async () => {
    vi.useFakeTimers();
    http = upstream({ dns: () => Response.json({ Status: 0, TC: true }) });
    const pending = runToolContract(whoisGetDns, { domain: 'example.com', types: ['A'] });
    await vi.runAllTimersAsync();
    expect((await pending).structuredContent).toMatchObject({
      error: {
        data: {
          reason: 'dns_response_failed',
          truncated: true,
        },
      },
    });
  });

  it('selects only a reachable PTR after a CNAME (#22)', async () => {
    http = upstream({
      dns: () =>
        Response.json({
          Status: 0,
          Answer: [
            { type: 5, name: '1.2.0.192.in-addr.arpa.', TTL: 60, data: '1.range.example.' },
            { type: 12, name: 'unrelated.example.', TTL: 60, data: 'wrong.example.' },
            { type: 12, name: '1.range.example.', TTL: 60, data: 'actual-host.example.' },
          ],
        }),
    });
    expect(await new DohService().ptrLookup('1.2.0.192.in-addr.arpa', createMockContext())).toEqual(
      { ptr: 'actual-host.example', ptr_status: 'found' },
    );
  });

  it('uses Cloudflare primary and NextDNS-only CAA with the legacy aggregate', async () => {
    http = upstream();
    const result = await new DohService().lookup('example.com', ['A', 'CAA'], createMockContext());
    expect(result).toMatchObject({ records: [], nxdomain: false, source: 'cloudflare' });
    expect(http.calls.map((call) => new URL(call.request.url).hostname)).toEqual([
      'cloudflare-dns.com',
      'dns.nextdns.io',
    ]);
  });

  it('falls back to NextDNS after a failed Cloudflare attempt', async () => {
    http = upstream({
      dns: (_type, url) =>
        url.hostname === 'cloudflare-dns.com'
          ? new Response(null, { status: 400 })
          : Response.json({ Status: 0 }),
    });
    const result = await new DohService().lookup('example.com', ['A'], createMockContext());
    expect(result.source).toBe('nextdns');
    expect(http.calls.map((call) => new URL(call.request.url).hostname)).toEqual([
      'cloudflare-dns.com',
      'dns.nextdns.io',
    ]);
  });

  it.each([0, 3])('preserves DNS status %s as data', async (Status) => {
    http = upstream({ dns: () => Response.json({ Status }) });
    const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: ['A'] });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      records: [],
      source: 'cloudflare',
      nxdomain: Status === 3,
    });
    expect(textOf(result)).toContain('cloudflare');
    expect(
      textOf(result)
        .split('\n')
        .filter((line) => line.startsWith('**NXDOMAIN:**')),
    ).toEqual([
      Status === 3
        ? '**NXDOMAIN:** Yes — at least one query returned NXDOMAIN'
        : '**NXDOMAIN:** No',
    ]);
    if (Status === 0) expect(textOf(result)).toContain('No records');
  });

  it('omitting types dispatches exactly the five defaults', async () => {
    http = upstream();
    const result = await runToolContract(whoisGetDns, { domain: 'example.com' });
    expect(result.isError).not.toBe(true);
    expect(http.calls.map((call) => new URL(call.request.url).searchParams.get('type'))).toEqual([
      'A',
      'AAAA',
      'MX',
      'TXT',
      'NS',
    ]);
  });
});

describe('DNS regression #9 and #10', () => {
  it('rejects explicit empty types at the public boundary before fetch (#9)', async () => {
    http = upstream();
    expect(whoisGetDns.input.safeParse({ domain: 'example.com', types: [] }).success).toBe(false);
    const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: [] });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: { code: -32602, data: { reason: 'invalid_arguments' } },
    });
    expect(result.structuredContent).not.toHaveProperty('source');
    expect(textOf(result)).toContain('types');
    expect(textOf(result)).toContain('1');
    expect(textOf(result)).not.toContain('**Source');
    expect(textOf(result)).not.toContain('nextdns');
    expect(textOf(result)).not.toContain('cloudflare');
    expect(http.calls).toHaveLength(0);
  });

  it.each(['primary', 'mixed', 'partial-fallback', 'all-fallback'] as const)(
    'attributes %s responses in dispatch order with deduplication (#10)',
    async (mode) => {
      http = upstream({
        dns: async (type, url) => {
          if (
            url.hostname === 'cloudflare-dns.com' &&
            (mode === 'all-fallback' || (mode === 'partial-fallback' && type === 'MX'))
          )
            return new Response(null, { status: 400 });
          if (type === 'A') await new Promise((resolve) => setTimeout(resolve, 15));
          return Response.json({
            Status: 0,
            Answer: [
              {
                type: type === 'A' ? 5 : 15,
                name: 'example.com',
                TTL: 60,
                data: `${type}.example.com`,
              },
            ],
          });
        },
      });
      const types: DnsRecordType[] = mode === 'mixed' ? ['A', 'CAA', 'A'] : ['A', 'MX', 'A'];
      const result = await runToolContract(whoisGetDns, { domain: 'example.com', types });
      const querySources = [
        { type: 'A', source: mode === 'all-fallback' ? 'nextdns' : 'cloudflare' },
        { type: types[1], source: mode === 'primary' ? 'cloudflare' : 'nextdns' },
      ];
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        source: mode === 'all-fallback' ? 'nextdns' : 'cloudflare',
        query_sources: querySources,
      });
      for (const query of querySources)
        expect(textOf(result)).toContain(`${query.type}: ${query.source}`);
      expect(http.calls).toHaveLength(
        mode === 'all-fallback' ? 4 : mode === 'partial-fallback' ? 3 : 2,
      );
    },
  );

  it.each([0, 3])('attributes empty status %s for every requested type (#10)', async (Status) => {
    http = upstream({ dns: () => Response.json({ Status }) });
    const result = await runToolContract(whoisGetDns, {
      domain: 'example.com',
      types: ['CAA', 'A'],
    });
    expect(result.structuredContent).toMatchObject({
      records: [],
      nxdomain: Status === 3,
      query_sources: [
        { type: 'CAA', source: 'nextdns' },
        { type: 'A', source: 'cloudflare' },
      ],
    });
    expect(textOf(result)).toContain('CAA: nextdns');
    expect(textOf(result)).toContain('A: cloudflare');
  });
});

describe('DoH retry and terminal paths', () => {
  it('exhausts primary retries, then consumes the third fallback attempt', async () => {
    vi.useFakeTimers();
    let fallbackAttempts = 0;
    http = upstream({
      dns: (_type, url) => {
        if (url.hostname === 'cloudflare-dns.com' || ++fallbackAttempts < 3)
          return new Response(null, { status: 503 });
        return Response.json({ Status: 0 });
      },
    });
    const resultPromise = runToolContract(whoisGetDns, { domain: 'example.com', types: ['MX'] });
    await vi.runAllTimersAsync();
    const result = await resultPromise;
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      source: 'nextdns',
      records: [],
      query_sources: [{ type: 'MX', source: 'nextdns' }],
    });
    expect(textOf(result)).toContain('MX: nextdns');
    expect(http.calls.map((call) => new URL(call.request.url).hostname)).toEqual([
      'cloudflare-dns.com',
      'cloudflare-dns.com',
      'cloudflare-dns.com',
      'dns.nextdns.io',
      'dns.nextdns.io',
      'dns.nextdns.io',
    ]);
  });
  it('consumes a successful primary retry without falling back', async () => {
    vi.useFakeTimers();
    let attempts = 0;
    http = upstream({
      dns: () =>
        ++attempts < 3 ? new Response(null, { status: 503 }) : Response.json({ Status: 0 }),
    });
    const pending = runToolContract(whoisGetDns, { domain: 'example.com', types: ['A'] });
    await vi.runAllTimersAsync();
    expect((await pending).structuredContent).toMatchObject({
      query_sources: [{ type: 'A', source: 'cloudflare' }],
    });
    expect(http.calls).toHaveLength(3);
  });
  it.each(['A', 'CAA'] as const)(
    'preserves terminal failure for %s without fabricated sources',
    async (type) => {
      http = upstream({ dns: () => new Response(null, { status: 400 }) });
      const result = await runToolContract(whoisGetDns, { domain: 'example.com', types: [type] });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).not.toHaveProperty('source');
      expect(result.structuredContent).not.toHaveProperty('query_sources');
      expect(http.calls).toHaveLength(type === 'CAA' ? 1 : 2);
      if (type === 'CAA')
        expect(
          http.calls.every((call) => new URL(call.request.url).hostname === 'dns.nextdns.io'),
        ).toBe(true);
    },
  );
});
