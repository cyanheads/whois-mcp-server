/**
 * @fileoverview DNS-over-HTTPS service — Cloudflare primary (1.1.1.1), NextDNS fallback.
 * CAA records always use NextDNS because Cloudflare returns raw hex wire format for them.
 * @module services/doh/doh-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import type { AppConfig } from '@cyanheads/mcp-ts-core/config';
import { serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import type { StorageService } from '@cyanheads/mcp-ts-core/storage';
import { fetchWithTimeout, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';
import type {
  DnsLookupResult,
  DnsRecordType,
  DohResponse,
  NormalizedDnsRecord,
  PtrLookupResult,
} from './types.js';
import { DNS_TYPE_NUMBERS } from './types.js';

const CLOUDFLARE_DOH = 'https://cloudflare-dns.com/dns-query';
const NEXTDNS_DOH = 'https://dns.nextdns.io';

/** Map numeric type to DnsRecordType string */
const TYPE_NUM_TO_NAME: Record<number, DnsRecordType> = Object.fromEntries(
  Object.entries(DNS_TYPE_NUMBERS).map(([k, v]) => [v, k as DnsRecordType]),
) as Record<number, DnsRecordType>;

export class DohService {
  /** Fetch DNS records for one type from a single DoH endpoint */
  private fetchSingleType(
    domain: string,
    type: DnsRecordType,
    baseUrl: string,
    timeoutMs: number,
    ctx: Context,
    source: 'cloudflare' | 'nextdns',
  ): Promise<DohResponse> {
    const url = `${baseUrl}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;

    return withRetry(
      async () => {
        ctx.signal.throwIfAborted();
        const response = await fetchWithTimeout(url, timeoutMs, ctx, {
          headers: {
            Accept: 'application/dns-json',
          },
          signal: ctx.signal,
        });
        const data = (await response.json()) as DohResponse;
        ctx.signal.throwIfAborted();
        if (data.TC === true || (data.Status !== 0 && data.Status !== 3)) {
          throw serviceUnavailable(
            `DNS ${type} query via ${source} failed: ${data.TC ? 'truncated response' : `RCODE ${data.Status}`}.`,
            {
              reason: 'dns_response_failed',
              type,
              resolver: source,
              status: data.Status,
              truncated: data.TC === true,
              recovery: { hint: 'Retry the DNS query later or choose another record type.' },
            },
          );
        }
        return data;
      },
      {
        operation: `doh.fetchSingleType.${source}`,
        context: ctx,
        maxRetries: getServerConfig().dohMaxRetries,
        baseDelayMs: 500,
        signal: ctx.signal,
      },
    );
  }

  /**
   * Look up one or more DNS record types for a domain.
   * CAA always uses NextDNS DoH (Cloudflare returns raw hex).
   * Falls back to NextDNS if Cloudflare fails for any type.
   * Returns `nxdomain: true` when NXDOMAIN (Status 3) is returned.
   */
  async lookup(domain: string, types: DnsRecordType[], ctx: Context): Promise<DnsLookupResult> {
    ctx.signal.throwIfAborted();
    const config = getServerConfig();
    const records: NormalizedDnsRecord[] = [];
    let nxdomain = false;
    const querySources = await Promise.all(
      [...new Set(types)].map(async (type) => {
        // CAA always via NextDNS; everything else Cloudflare first
        const primaryUrl = type === 'CAA' ? NEXTDNS_DOH : CLOUDFLARE_DOH;
        let source: 'cloudflare' | 'nextdns' = type === 'CAA' ? 'nextdns' : 'cloudflare';

        let resp: DohResponse;
        try {
          resp = await this.fetchSingleType(
            domain,
            type,
            primaryUrl,
            config.dohTimeoutMs,
            ctx,
            source,
          );
        } catch (error) {
          ctx.signal.throwIfAborted();
          if (type === 'CAA') throw error;
          // Fallback to NextDNS for non-CAA types
          resp = await this.fetchSingleType(
            domain,
            type,
            NEXTDNS_DOH,
            config.dohTimeoutMs,
            ctx,
            'nextdns',
          );
          source = 'nextdns';
        }

        // NXDOMAIN describes the terminal name; preceding CNAME answers remain useful.
        if (resp.Status === 3) nxdomain = true;

        for (const answer of resp.Answer ?? []) {
          const typeName = TYPE_NUM_TO_NAME[answer.type];
          if (!typeName) continue; // unknown numeric type — skip
          records.push({
            type: typeName,
            name: answer.name,
            ttl: answer.TTL,
            data: answer.data,
          });
        }
        return { type, source };
      }),
    );

    const source = querySources.some((query) => query.source === 'cloudflare')
      ? 'cloudflare'
      : 'nextdns';
    return { domain, nxdomain, records, source, query_sources: querySources };
  }

  /**
   * Perform a reverse DNS (PTR) lookup for an IP address.
   * IPv4: reverses octets + .in-addr.arpa
   * IPv6: reverses nibbles + .ip6.arpa
   * Follows reachable aliases under one deadline; distinguishes absence from failure.
   */
  async ptrLookup(ptrName: string, ctx: Context): Promise<PtrLookupResult> {
    const signal = AbortSignal.any([
      ctx.signal,
      AbortSignal.timeout(getServerConfig().dohTimeoutMs),
    ]);
    const ptrCtx = { ...ctx, signal };
    const normalize = (name: string) => name.toLowerCase().replace(/\.$/, '');
    let owner = normalize(ptrName);
    let hops = 0;
    const visited = new Set([owner]);
    try {
      while (true) {
        signal.throwIfAborted();
        const result = await this.lookup(owner, ['PTR'], ptrCtx);
        if (result.nxdomain) return { ptr: null, ptr_status: 'not_found' };
        let followed = false;
        while (true) {
          const ptr = result.records.find(
            (record) => record.type === 'PTR' && normalize(record.name) === owner,
          );
          if (ptr) return { ptr: normalize(ptr.data), ptr_status: 'found' };
          const alias = result.records.find(
            (record) => record.type === 'CNAME' && normalize(record.name) === owner,
          );
          if (!alias) break;
          const target = normalize(alias.data);
          if (visited.has(target) || hops === 5)
            throw serviceUnavailable('Reverse DNS alias loop or five-transition limit reached.');
          visited.add(target);
          owner = target;
          hops++;
          followed = true;
        }
        if (!followed) return { ptr: null, ptr_status: 'not_found' };
      }
    } catch (error) {
      ctx.signal.throwIfAborted();
      return {
        ptr: null,
        ptr_status: 'failed',
        ptr_source_error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

// ─── Init/accessor pattern ────────────────────────────────────────────────────

let _service: DohService | undefined;

export function initDohService(_config: AppConfig, _storage: StorageService): void {
  _service = new DohService();
}

export function getDohService(): DohService {
  if (!_service) {
    throw new Error('DohService not initialized — call initDohService() in setup()');
  }
  return _service;
}
