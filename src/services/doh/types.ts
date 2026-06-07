/**
 * @fileoverview DNS-over-HTTPS service types — raw upstream and normalized shapes.
 * @module services/doh/types
 */

/** DNS record types supported by the server */
export type DnsRecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME' | 'SOA' | 'CAA' | 'PTR';

/** DNS type numeric codes */
export const DNS_TYPE_NUMBERS: Record<DnsRecordType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
};

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
  records: NormalizedDnsRecord[];
  source: 'cloudflare' | 'nextdns';
}
