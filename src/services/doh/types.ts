/**
 * @fileoverview DNS-over-HTTPS service types — raw upstream and normalized shapes.
 * @module services/doh/types
 */

/** DNS type numeric codes */
export const DNS_TYPE_NUMBERS = {
  A: 1,
  AAAA: 28,
  MX: 15,
  TXT: 16,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  CAA: 257,
  PTR: 12,
  SRV: 33,
  DS: 43,
  DNSKEY: 48,
  TLSA: 52,
  HTTPS: 65,
} as const;

/** DNS record types supported by the server */
export type DnsRecordType = keyof typeof DNS_TYPE_NUMBERS;

/** Raw DNS answer from DoH JSON API */
export interface DohAnswer {
  data: string;
  name: string;
  TTL: number;
  type: number;
}

/** Raw DoH JSON response */
export interface DohResponse {
  AD?: boolean;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
  CD?: boolean;
  Question?: Array<{ name: string; type: number }>;
  RA?: boolean;
  RD?: boolean;
  Status: number;
  TC?: boolean;
}

/** A single normalized DNS record */
export interface NormalizedDnsRecord {
  data: string;
  name: string;
  ttl: number;
  type: DnsRecordType;
}

/** Result of a multi-type DNS lookup */
export interface DnsLookupResult {
  domain: string;
  nxdomain: boolean;
  query_sources: Array<{ type: DnsRecordType; source: 'cloudflare' | 'nextdns' }>;
  records: NormalizedDnsRecord[];
  source: 'cloudflare' | 'nextdns';
}

/** Best-effort reverse lookup distinguishes a hostname, successful absence and failure. */
export type PtrLookupResult =
  | { ptr: string; ptr_status: 'found' }
  | { ptr: null; ptr_status: 'not_found' }
  | { ptr: null; ptr_status: 'failed'; ptr_source_error: string };
