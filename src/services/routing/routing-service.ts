/**
 * @fileoverview Best-effort RIPEstat RIS routing observations, separate from registry ownership.
 * @module services/routing/routing-service
 */
import { type Context, z } from '@cyanheads/mcp-ts-core';
import type { AppConfig } from '@cyanheads/mcp-ts-core/config';
import { serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import type { StorageService } from '@cyanheads/mcp-ts-core/storage';
import { fetchWithTimeout } from '@cyanheads/mcp-ts-core/utils';
import { validateIp } from '@/services/rdap/rdap-service.js';

const ENDPOINT = 'https://stat.ripe.net/data/network-info/data.json';
const SNAPSHOT_BASIS =
  'RISwhois routing dumps updated every eight hours; observations are not registry ownership.';
const TIMEOUT_MS = 3000;
const ResponseSchema = z.object({
  status: z.literal('ok'),
  data: z.object({
    prefix: z.string(),
    asns: z.array(
      z
        .string()
        .regex(/^\d+$/)
        .refine((value) => Number(value) >= 1 && Number(value) <= 4294967295),
    ),
  }),
});

/** Separately attributed routing result; missing observations are distinct from failed requests. */
export interface RoutingDetail {
  next_tool: 'whois_lookup_asn';
  origin_asns: string[];
  prefix: string | null;
  recovery?: string;
  snapshot_basis: string;
  source: string;
  source_error?: string;
  status: 'found' | 'not_found' | 'failed';
}

/** Single-attempt RIPEstat client with one deadline covering fetch and body parsing. */
export class RoutingService {
  async lookup(base: string, ctx: Context): Promise<RoutingDetail> {
    ctx.signal.throwIfAborted();
    const controller = new AbortController();
    const timer = setTimeout(
      () =>
        controller.abort(
          new DOMException('Routing lookup exceeded its 3000 ms deadline.', 'TimeoutError'),
        ),
      TIMEOUT_MS,
    );
    const signal = AbortSignal.any([ctx.signal, controller.signal]);
    const aborted = Promise.withResolvers<never>();
    const onAbort = () => aborted.reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    const metadata = {
      source: ENDPOINT,
      snapshot_basis: SNAPSHOT_BASIS,
      next_tool: 'whois_lookup_asn' as const,
    };
    try {
      const { data } = await Promise.race([
        (async () => {
          const response = await fetchWithTimeout(
            `${ENDPOINT}?resource=${encodeURIComponent(base)}`,
            TIMEOUT_MS,
            ctx,
            {
              headers: { Accept: 'application/json' },
              signal,
            },
          );
          const parsed = ResponseSchema.safeParse(await response.json());
          signal.throwIfAborted();
          if (!parsed.success)
            throw serviceUnavailable(
              'RIPEstat returned malformed or unsuccessful Network Info data.',
            );
          const { prefix, asns } = parsed.data.data;
          const parsedPrefix = prefix ? validateIp(prefix) : undefined;
          if (
            (prefix && (!parsedPrefix?.valid || !parsedPrefix.hasCidr)) ||
            Boolean(prefix) !== Boolean(asns.length)
          )
            throw serviceUnavailable(
              'RIPEstat returned inconsistent routing prefix and origin data.',
            );
          if (parsedPrefix?.valid) {
            const address = validateIp(base);
            const width = parsedPrefix.isIpv6 ? 128 : 32;
            const prefixLength = Number(prefix.split('/')[1]);
            const hostBits = BigInt(width - prefixLength);
            if (
              !address.valid ||
              address.isIpv6 !== parsedPrefix.isIpv6 ||
              prefixLength > width ||
              address.value >> hostBits !== parsedPrefix.value >> hostBits
            )
              throw serviceUnavailable(
                'RIPEstat returned a routing prefix that does not contain the queried address.',
              );
          }
          return parsed.data;
        })(),
        aborted.promise,
      ]);
      return {
        ...metadata,
        status: data.prefix ? 'found' : 'not_found',
        prefix: data.prefix || null,
        origin_asns: data.asns.map((asn) => `AS${Number(asn)}`),
      };
    } catch (error) {
      ctx.signal.throwIfAborted();
      return {
        ...metadata,
        status: 'failed',
        prefix: null,
        origin_asns: [],
        source_error: error instanceof Error ? error.message : String(error),
        recovery:
          'Retry whois_lookup_ip with include_routing enabled later; registry and PTR data remain usable.',
      };
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
    }
  }
}

let service: RoutingService | undefined;
/** Initialize the stateless routing client during application setup. */
export function initRoutingService(_config: AppConfig, _storage: StorageService): void {
  service = new RoutingService();
}
/** Return the initialized routing client. */
export function getRoutingService(): RoutingService {
  if (!service)
    throw new Error('RoutingService not initialized — call initRoutingService() in setup()');
  return service;
}
