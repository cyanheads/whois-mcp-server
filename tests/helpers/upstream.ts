/**
 * @fileoverview Strict HTTP fixtures around the real RDAP and DoH services.
 * @module tests/helpers/upstream
 */

import { createFetchMock } from '@cyanheads/mcp-ts-core/testing';
import { vi } from 'vitest';
import * as doh from '@/services/doh/doh-service.js';
import type { DnsRecordType, DohResponse } from '@/services/doh/types.js';
import * as rdap from '@/services/rdap/rdap-service.js';

/** Install fresh real services and route only their outbound HTTP boundary. */
export function upstream(
  options: {
    dns?: (type: DnsRecordType, url: URL) => Response | Promise<Response>;
    rdap?: (url: URL) => Response;
    coverage?: boolean;
  } = {},
) {
  vi.spyOn(rdap, 'getRdapService').mockReturnValue(new rdap.RdapService());
  vi.spyOn(doh, 'getDohService').mockReturnValue(new doh.DohService());
  const http = createFetchMock([
    {
      match: (request) => new URL(request.url).origin === 'https://data.iana.org',
      respond: (request) => {
        const path = new URL(request.url).pathname;
        const ranges = path.endsWith('dns.json')
          ? ['com']
          : path.endsWith('asn.json')
            ? ['1-4294967295']
            : path.endsWith('ipv6.json')
              ? ['::/0']
              : ['0.0.0.0/1', '128.0.0.0/1'];
        return Response.json({
          services: options.coverage === false ? [] : [[ranges, ['https://rdap.test']]],
        });
      },
    },
    {
      match: (request) => new URL(request.url).origin === 'https://rdap.test',
      respond: (request) =>
        options.rdap?.(new URL(request.url)) ??
        Response.json({
          ldhName: 'EXAMPLE.COM',
          name: 'EXAMPLE',
          handle: 'EXAMPLE-HANDLE',
          links: [{ rel: 'self', href: 'https://rdap.arin.net/registry/object' }],
        }),
    },
    {
      match: (request) =>
        ['https://cloudflare-dns.com', 'https://dns.nextdns.io'].includes(
          new URL(request.url).origin,
        ),
      respond: (request) => {
        const url = new URL(request.url);
        return (
          options.dns?.(url.searchParams.get('type') as DnsRecordType, url) ??
          Response.json({ Status: 0 } satisfies DohResponse)
        );
      },
    },
  ]);
  http.install();
  return http;
}

/** Collect every text block in a contract result. */
export function textOf(result: { content: readonly { type: string; text?: unknown }[] }): string {
  return result.content
    .filter((block) => block.type === 'text')
    .map((block) => block.text)
    .join('\n');
}
