/**
 * @fileoverview DNS-over-HTTPS service — Cloudflare primary (1.1.1.1), Google fallback (8.8.8.8).
 * CAA records always use Google DoH because Cloudflare returns raw hex wire format for them.
 * @module services/doh/doh-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import type { AppConfig } from '@cyanheads/mcp-ts-core/config';
import type { StorageService } from '@cyanheads/mcp-ts-core/storage';
import { fetchWithTimeout, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';
import type { DnsLookupResult, DnsRecordType, DohResponse, NormalizedDnsRecord } from './types.js';
import { DNS_TYPE_NUMBERS } from './types.js';

const CLOUDFLARE_DOH = 'https://cloudflare-dns.com/dns-query';
const GOOGLE_DOH = 'https://dns.google/resolve';

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
    source: 'cloudflare' | 'google',
  ): Promise<DohResponse> {
    const url = `${baseUrl}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
    const reqCtx = { requestId: ctx.requestId, tenantId: ctx.tenantId, timestamp: ctx.timestamp };

    return withRetry(
      async () => {
        const response = await fetchWithTimeout(url, timeoutMs, reqCtx, {
          headers: {
            Accept: 'application/dns-json',
          },
          signal: ctx.signal,
        });
        return response.json() as Promise<DohResponse>;
      },
      {
        operation: `doh.fetchSingleType.${source}`,
        context: reqCtx,
        maxRetries: getServerConfig().dohMaxRetries,
        baseDelayMs: 500,
        signal: ctx.signal,
      },
    );
  }

  /**
   * Look up one or more DNS record types for a domain.
   * CAA always uses Google DoH (Cloudflare returns raw hex).
   * Falls back to Google if Cloudflare fails for any type.
   * Returns `nxdomain: true` when NXDOMAIN (Status 3) is returned.
   */
  async lookup(domain: string, types: DnsRecordType[], ctx: Context): Promise<DnsLookupResult> {
    const config = getServerConfig();
    const records: NormalizedDnsRecord[] = [];
    let nxdomain = false;
    // Track actual resolvers used: cloudflare = at least one non-CAA type used Cloudflare primary;
    // google = all types used Google (either CAA-primary or Cloudflare-fallback)
    let usedCloudflare = false;

    await Promise.all(
      types.map(async (type) => {
        // CAA always via Google; everything else Cloudflare first
        const primaryUrl = type === 'CAA' ? GOOGLE_DOH : CLOUDFLARE_DOH;
        const primarySource: 'cloudflare' | 'google' = type === 'CAA' ? 'google' : 'cloudflare';

        let resp: DohResponse;
        try {
          resp = await this.fetchSingleType(
            domain,
            type,
            primaryUrl,
            config.dohTimeoutMs,
            ctx,
            primarySource,
          );
          // Only count as cloudflare when we successfully used Cloudflare (not CAA)
          if (type !== 'CAA') usedCloudflare = true;
        } catch {
          // Fallback to Google for non-CAA types
          resp = await this.fetchSingleType(
            domain,
            type,
            GOOGLE_DOH,
            config.dohTimeoutMs,
            ctx,
            'google',
          );
        }

        if (resp.Status === 3) {
          // NXDOMAIN — domain does not exist in DNS
          nxdomain = true;
          return;
        }

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
      }),
    );

    const source: 'cloudflare' | 'google' = usedCloudflare ? 'cloudflare' : 'google';
    return { domain, nxdomain, records, source };
  }

  /**
   * Perform a reverse DNS (PTR) lookup for an IP address.
   * IPv4: reverses octets + .in-addr.arpa
   * IPv6: reverses nibbles + .ip6.arpa
   * Returns null if the PTR lookup fails or returns no answer.
   */
  async ptrLookup(ptrName: string, ctx: Context): Promise<string | null> {
    try {
      const result = await this.lookup(ptrName, ['PTR'], ctx);
      if (result.nxdomain || result.records.length === 0) return null;
      const first = result.records[0];
      if (!first) return null;
      return first.data.replace(/\.$/, '') || null;
    } catch {
      return null;
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
