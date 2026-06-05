/**
 * @fileoverview RDAP service — IANA bootstrap-driven domain, IP, and ASN lookups.
 * Caches the IANA bootstrap JSON for 24 hours to avoid a bootstrap hop on every query.
 * @module services/rdap/rdap-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import type { AppConfig } from '@cyanheads/mcp-ts-core/config';
import { notFound, serviceUnavailable, validationError } from '@cyanheads/mcp-ts-core/errors';
import type { StorageService } from '@cyanheads/mcp-ts-core/storage';
import { fetchWithTimeout, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';
import type {
  IanaBootstrap,
  NormalizedAsn,
  NormalizedDomain,
  NormalizedIpNetwork,
  RdapAutnumRaw,
  RdapDomainRaw,
  RdapEntity,
  RdapIpNetworkRaw,
  VCard,
} from './types.js';

// IANA bootstrap endpoints
const IANA_DNS_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';
const IANA_IPV4_BOOTSTRAP = 'https://data.iana.org/rdap/ipv4.json';
const IANA_IPV6_BOOTSTRAP = 'https://data.iana.org/rdap/ipv6.json';
const IANA_ASN_BOOTSTRAP = 'https://data.iana.org/rdap/asn.json';

const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000; // 24h

// Private/reserved IPv4 ranges
const PRIVATE_IPV4_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^100\.(6[4-9]|[7-9]\d|1([01]\d|2[0-7]))\./, // CGNAT 100.64-100.127
  /^0\./,
  /^255\./,
];

// Private/reserved IPv6 ranges (string prefix checks)
const PRIVATE_IPV6_PREFIXES = [
  '::1', // loopback
  'fc', // ULA fc00::/7
  'fd', // ULA fd00::/7
  'fe80', // link-local fe80::/10
];

function isPrivateIpv4(ip: string): boolean {
  return PRIVATE_IPV4_RANGES.some((r) => r.test(ip));
}

function isPrivateIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  return PRIVATE_IPV6_PREFIXES.some((p) => lower.startsWith(p));
}

/** Check if an IP or CIDR base is private/reserved. */
function isPrivateIp(ip: string): boolean {
  const base = ip.split('/')[0] ?? '';
  if (base.includes(':')) return isPrivateIpv6(base);
  return isPrivateIpv4(base);
}

/** Simple IPv4 validation */
function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = parseInt(p, 10);
    return !Number.isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

/** Simple IPv6 validation — accepts compressed forms */
function isValidIpv6(ip: string): boolean {
  if (!ip.includes(':')) return false;
  if (ip.split(':').length > 8) return false;
  return /^[0-9a-fA-F:]+$/.test(ip);
}

/** Validate an IP address or CIDR notation */
export function validateIp(ip: string): { valid: boolean; isIpv6: boolean; hasCidr: boolean } {
  const parts = ip.split('/');
  const base = parts[0] ?? '';
  const hasCidr = parts.length === 2;

  if (hasCidr) {
    const prefix = parseInt(parts[1] ?? '', 10);
    if (Number.isNaN(prefix) || prefix < 0) return { valid: false, isIpv6: false, hasCidr: true };
  }

  const isIpv6 = base.includes(':');
  if (isIpv6) {
    if (hasCidr && parseInt(parts[1] ?? '129', 10) > 128)
      return { valid: false, isIpv6: true, hasCidr: true };
    return { valid: isValidIpv6(base), isIpv6: true, hasCidr };
  }

  if (hasCidr && parseInt(parts[1] ?? '33', 10) > 32)
    return { valid: false, isIpv6: false, hasCidr: true };
  return { valid: isValidIpv4(base), isIpv6: false, hasCidr };
}

/** Build reverse PTR query name from an IPv4 address */
export function ipv4ToPtr(ip: string): string {
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

/** Expand a compressed IPv6 address to a full 128-bit BigInt */
function ipv6ToBigInt(ip: string): bigint {
  let groups: string[];
  if (ip.includes('::')) {
    const parts = ip.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    groups = [...left, ...Array<string>(missing).fill('0'), ...right];
  } else {
    groups = ip.split(':');
  }
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || '0', 16)), 0n);
}

/** Build reverse PTR query name from an IPv6 address */
export function ipv6ToPtr(ip: string): string {
  let hex: string;
  // Handle :: compression
  if (ip.includes('::')) {
    const parts = ip.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    const full = [...left, ...Array(missing).fill('0'), ...right];
    hex = full.map((g) => g.padStart(4, '0')).join('');
  } else {
    hex = ip
      .split(':')
      .map((g) => g.padStart(4, '0'))
      .join('');
  }
  return `${hex.split('').reverse().join('.')}.ip6.arpa`;
}

/** Extract top-level TLD (last label) */
function extractToplevelTld(domain: string): string {
  const labels = domain.toLowerCase().split('.');
  return labels[labels.length - 1] ?? '';
}

/** Normalize a domain to its two-label suffix for bootstrap lookup */
function extractTwoLabelSuffix(domain: string): string {
  const labels = domain.toLowerCase().split('.');
  if (labels.length < 2) return '';
  return labels.slice(-2).join('.');
}

/** Extract vCard field value by field name */
function vcardField(vcard: VCard, fieldName: string): string | undefined {
  for (const entry of vcard) {
    if (Array.isArray(entry) && entry[0] === fieldName) {
      const val = entry[3 as keyof typeof entry];
      if (typeof val === 'string') return val;
      if (Array.isArray(val) && typeof val[0] === 'string') return val[0];
    }
  }
  return;
}

/** Extract fn (full name / org name) from an entity's vcard */
function entityName(entity: RdapEntity): string | undefined {
  if (!entity.vcardArray) return;
  const vcard = entity.vcardArray[1];
  return vcardField(vcard, 'fn');
}

/** Extract email from an entity's vcard */
function entityEmail(entity: RdapEntity): string | undefined {
  if (!entity.vcardArray) return;
  const vcard = entity.vcardArray[1];
  return vcardField(vcard, 'email');
}

/** Find nested entity by role, searching recursively */
function findEntityByRole(entities: RdapEntity[], role: string): RdapEntity | undefined {
  for (const e of entities) {
    if (e.roles?.includes(role)) return e;
    if (e.entities) {
      const found = findEntityByRole(e.entities, role);
      if (found) return found;
    }
  }
  return;
}

/** Extract registrar IANA ID from publicIds */
function registrarIanaId(entity: RdapEntity): string | undefined {
  return entity.publicIds?.find((p) => p.type === 'IANA Registrar ID')?.identifier;
}

/** Normalize RDAP domain response to our output shape */
function normalizeDomain(raw: RdapDomainRaw): NormalizedDomain & { rdap_coverage: true } {
  const events = raw.events ?? [];
  const getDate = (action: string): string | undefined =>
    events.find((e) => e.eventAction === action)?.eventDate;

  const nameservers = (raw.nameservers ?? [])
    .map((ns) => (ns.ldhName ?? ns.unicodeName ?? '').toLowerCase())
    .filter(Boolean);

  const entities = raw.entities ?? [];
  const registrarEntity = findEntityByRole(entities, 'registrar');
  const registrar = registrarEntity ? entityName(registrarEntity) : undefined;
  const registrarIanaIdVal = registrarEntity ? registrarIanaId(registrarEntity) : undefined;

  const registrantEntity = findEntityByRole(entities, 'registrant');
  const registrantOrg = registrantEntity ? entityName(registrantEntity) : undefined;
  const registrantRedacted = !registrantOrg;

  const rdapLastUpdated = getDate('last update of RDAP database');
  const createdDate = getDate('registration');
  const updatedDate = getDate('last changed');
  const expiryDate = getDate('expiration');
  const domainName = (raw.ldhName ?? raw.unicodeName ?? '').toLowerCase();

  // Build with exactOptionalPropertyTypes compliance using type assertion on optional fields
  const result: NormalizedDomain & { rdap_coverage: true } = {
    domain: domainName,
    rdap_coverage: true,
    status: raw.status ?? [],
    nameservers,
    dnssec_signed: raw.secureDNS?.delegationSigned ?? false,
    registrant_redacted: registrantRedacted,
  };

  if (raw.handle !== undefined) result.handle = raw.handle;
  if (registrar !== undefined) result.registrar = registrar;
  if (registrarIanaIdVal !== undefined) result.registrar_iana_id = registrarIanaIdVal;
  if (createdDate !== undefined) result.created_date = createdDate;
  if (updatedDate !== undefined) result.updated_date = updatedDate;
  if (expiryDate !== undefined) result.expiry_date = expiryDate;
  if (rdapLastUpdated !== undefined) result.rdap_last_updated = rdapLastUpdated;
  if (registrantOrg !== undefined) result.registrant_org = registrantOrg;

  return result;
}

/** Normalize RDAP IP network response */
function normalizeIpNetwork(raw: RdapIpNetworkRaw, ip: string): NormalizedIpNetwork {
  const entities = raw.entities ?? [];
  const registrant = findEntityByRole(entities, 'registrant');
  const abuse = findEntityByRole(entities, 'abuse');
  const orgName = registrant ? entityName(registrant) : undefined;
  const abuseEmail = abuse ? entityEmail(abuse) : undefined;

  let cidr: string | undefined;
  if (raw.cidr0_cidrs && raw.cidr0_cidrs.length > 0) {
    const c = raw.cidr0_cidrs[0];
    if (c) {
      if (c.v4prefix !== undefined && c.length !== undefined) cidr = `${c.v4prefix}/${c.length}`;
      else if (c.v6prefix !== undefined && c.length !== undefined)
        cidr = `${c.v6prefix}/${c.length}`;
    }
  }

  const selfLink = raw.links?.find((l) => l.rel === 'self')?.href ?? '';
  let rdapSource: string | undefined;
  if (selfLink.includes('arin.net')) rdapSource = 'ARIN';
  else if (selfLink.includes('ripe.net')) rdapSource = 'RIPE';
  else if (selfLink.includes('apnic.net')) rdapSource = 'APNIC';
  else if (selfLink.includes('lacnic.net')) rdapSource = 'LACNIC';
  else if (selfLink.includes('afrinic.net')) rdapSource = 'AFRINIC';

  const result: NormalizedIpNetwork = { ip, ptr: null };

  if (raw.handle !== undefined) result.handle = raw.handle;
  if (raw.startAddress !== undefined) result.start_address = raw.startAddress;
  if (raw.endAddress !== undefined) result.end_address = raw.endAddress;
  if (cidr !== undefined) result.cidr = cidr;
  if (raw.ipVersion !== undefined) result.ip_version = raw.ipVersion;
  if (raw.name !== undefined) result.name = raw.name;
  if (raw.type !== undefined) result.type = raw.type;
  if (raw.country !== undefined && raw.country !== null) result.country = raw.country;
  if (orgName !== undefined) result.org_name = orgName;
  if (abuseEmail !== undefined) result.abuse_email = abuseEmail;
  if (rdapSource !== undefined) result.rdap_source = rdapSource;

  return result;
}

/** Normalize RDAP autnum (ASN) response */
function normalizeAutnum(raw: RdapAutnumRaw, asn: string): NormalizedAsn {
  const entities = raw.entities ?? [];
  const registrant = findEntityByRole(entities, 'registrant');
  const orgName = registrant ? entityName(registrant) : undefined;

  const selfLink = raw.links?.find((l) => l.rel === 'self')?.href ?? '';
  let rir: string | undefined;
  if (selfLink.includes('arin.net')) rir = 'ARIN';
  else if (selfLink.includes('ripe.net')) rir = 'RIPE';
  else if (selfLink.includes('apnic.net')) rir = 'APNIC';
  else if (selfLink.includes('lacnic.net')) rir = 'LACNIC';
  else if (selfLink.includes('afrinic.net')) rir = 'AFRINIC';

  const result: NormalizedAsn = { asn };

  if (raw.handle !== undefined) result.handle = raw.handle;
  if (raw.startAutnum !== undefined) result.start_autnum = raw.startAutnum;
  if (raw.endAutnum !== undefined) result.end_autnum = raw.endAutnum;
  if (raw.name !== undefined) result.name = raw.name;
  if (raw.type !== undefined) result.type = raw.type;
  if (raw.country !== undefined && raw.country !== null) result.country = raw.country;
  if (orgName !== undefined) result.org_name = orgName;
  if (rir !== undefined) result.rir = rir;

  return result;
}

// ─── Service class ────────────────────────────────────────────────────────────

export class RdapService {
  private bootstrapCache: Map<string, { data: IanaBootstrap; fetchedAt: number }> = new Map();

  /** Fetch and cache a bootstrap JSON from IANA */
  private async fetchBootstrap(url: string, ctx: Context): Promise<IanaBootstrap> {
    const cached = this.bootstrapCache.get(url);
    if (cached && Date.now() - cached.fetchedAt < BOOTSTRAP_TTL_MS) {
      return cached.data;
    }

    const config = getServerConfig();
    const reqCtx = { requestId: ctx.requestId, tenantId: ctx.tenantId, timestamp: ctx.timestamp };
    const response = await fetchWithTimeout(url, config.rdapTimeoutMs, reqCtx, {
      headers: { Accept: 'application/json' },
      signal: ctx.signal,
    });
    const data = (await response.json()) as IanaBootstrap;
    this.bootstrapCache.set(url, { data, fetchedAt: Date.now() });
    return data;
  }

  /** Find the RDAP server URL for a domain's TLD via IANA bootstrap */
  async findDomainRdapServer(domain: string, ctx: Context): Promise<string | null> {
    const bootstrap = await this.fetchBootstrap(IANA_DNS_BOOTSTRAP, ctx);

    const twoLabel = extractTwoLabelSuffix(domain);
    const singleLabel = extractToplevelTld(domain);

    for (const candidate of [twoLabel, singleLabel]) {
      if (!candidate) continue;
      for (const [tlds, servers] of bootstrap.services) {
        if (tlds.includes(candidate) && servers.length > 0) {
          return servers[0]?.replace(/\/$/, '') ?? null;
        }
      }
    }
    return null;
  }

  /** Find the RDAP server URL for an IP address via IANA bootstrap */
  async findIpRdapServer(ip: string, isIpv6: boolean, ctx: Context): Promise<string | null> {
    const bootstrapUrl = isIpv6 ? IANA_IPV6_BOOTSTRAP : IANA_IPV4_BOOTSTRAP;
    const bootstrap = await this.fetchBootstrap(bootstrapUrl, ctx);

    if (isIpv6) {
      // IPv6: match against CIDR prefixes in the bootstrap using bigint arithmetic
      const base = ip.split('/')[0] ?? '';
      const ipBig = ipv6ToBigInt(base);
      for (const [cidrs, servers] of bootstrap.services) {
        for (const cidr of cidrs) {
          const slash = cidr.indexOf('/');
          if (slash === -1) continue;
          const net = cidr.slice(0, slash);
          const prefixLen = parseInt(cidr.slice(slash + 1), 10);
          if (Number.isNaN(prefixLen) || prefixLen < 0 || prefixLen > 128) continue;
          const netBig = ipv6ToBigInt(net);
          const mask = prefixLen === 0 ? 0n : ~((1n << BigInt(128 - prefixLen)) - 1n);
          if ((netBig & mask) === (ipBig & mask) && servers.length > 0) {
            return servers[0]?.replace(/\/$/, '') ?? null;
          }
        }
      }
      return null;
    }

    // IPv4: match against CIDR prefixes in the bootstrap
    const base = ip.split('/')[0] ?? '';
    const parts = base.split('.').map(Number);

    for (const [cidrs, servers] of bootstrap.services) {
      for (const cidr of cidrs) {
        const cidrParts = cidr.split('/');
        const net = cidrParts[0] ?? '';
        const bits = cidrParts[1] ?? '0';
        const prefixLen = parseInt(bits, 10);
        const netParts = net.split('.').map(Number);

        if (netParts.length !== 4 || parts.length !== 4) continue;
        const mask = ~((1 << (32 - prefixLen)) - 1);
        const [n0, n1, n2, n3] = netParts as [number, number, number, number];
        const [p0, p1, p2, p3] = parts as [number, number, number, number];
        const netNum = (n0 << 24) | (n1 << 16) | (n2 << 8) | n3;
        const ipNum = (p0 << 24) | (p1 << 16) | (p2 << 8) | p3;
        if ((netNum & mask) === (ipNum & mask) && servers.length > 0) {
          return servers[0]?.replace(/\/$/, '') ?? null;
        }
      }
    }
    return null;
  }

  /** Find the RDAP server URL for an ASN via IANA bootstrap */
  async findAsnRdapServer(asnNum: number, ctx: Context): Promise<string | null> {
    const bootstrap = await this.fetchBootstrap(IANA_ASN_BOOTSTRAP, ctx);

    for (const [ranges, servers] of bootstrap.services) {
      for (const range of ranges) {
        const rangeParts = range.split('-').map(Number);
        const start = rangeParts[0];
        const rangeEnd = rangeParts.length > 1 ? rangeParts[1] : start;
        if (start === undefined || rangeEnd === undefined) continue;
        if (asnNum >= start && asnNum <= rangeEnd && servers.length > 0) {
          return servers[0]?.replace(/\/$/, '') ?? null;
        }
      }
    }
    return null;
  }

  /** Look up a domain registration record via RDAP */
  async lookupDomain(domain: string, ctx: Context): Promise<NormalizedDomain> {
    const rdapServer = await this.findDomainRdapServer(domain, ctx);

    if (!rdapServer) {
      return {
        domain: domain.toLowerCase(),
        rdap_coverage: false,
        status: [],
        nameservers: [],
        dnssec_signed: false,
        registrant_redacted: false,
      };
    }

    const config = getServerConfig();
    const url = `${rdapServer}/domain/${encodeURIComponent(domain.toLowerCase())}`;
    const reqCtx = { requestId: ctx.requestId, tenantId: ctx.tenantId, timestamp: ctx.timestamp };

    try {
      const raw = await withRetry(
        async () => {
          const response = await fetchWithTimeout(url, config.rdapTimeoutMs, reqCtx, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: ctx.signal,
          });
          return response.json() as Promise<RdapDomainRaw>;
        },
        {
          operation: 'rdap.lookupDomain',
          context: reqCtx,
          maxRetries: config.rdapMaxRetries,
          baseDelayMs: 1000,
          signal: ctx.signal,
          isTransient: (err: unknown) => {
            // 404 is NOT transient — domain is not registered; don't retry
            if (err instanceof Error) {
              const msg = err.message;
              if (msg.includes('404') || msg.includes('Not Found') || msg.includes('NotFound')) {
                return false;
              }
            }
            return true;
          },
        },
      );
      return normalizeDomain(raw);
    } catch (err) {
      // RDAP 404 on a domain lookup means the domain is not registered
      if (
        err instanceof Error &&
        (err.message.includes('404') ||
          err.message.includes('Not Found') ||
          err.message.includes('NotFound'))
      ) {
        throw notFound(`Domain "${domain}" is not registered (RDAP 404).`, {
          reason: 'domain_not_found',
          domain: domain.toLowerCase(),
        });
      }
      throw err;
    }
  }

  /**
   * Check domain availability via RDAP.
   * Returns `{ available: true }` on 404, normalized record on 200,
   * or `{ available: null }` when TLD has no RDAP coverage.
   */
  async checkAvailability(
    domain: string,
    ctx: Context,
  ): Promise<
    | { available: true }
    | { available: false; record: NormalizedDomain }
    | { available: null; rdap_coverage: false }
  > {
    const rdapServer = await this.findDomainRdapServer(domain, ctx);

    if (!rdapServer) {
      return { available: null, rdap_coverage: false };
    }

    const config = getServerConfig();
    const url = `${rdapServer}/domain/${encodeURIComponent(domain.toLowerCase())}`;
    const reqCtx = { requestId: ctx.requestId, tenantId: ctx.tenantId, timestamp: ctx.timestamp };

    try {
      const raw = await withRetry(
        async () => {
          const response = await fetchWithTimeout(url, config.rdapTimeoutMs, reqCtx, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: ctx.signal,
          });
          return response.json() as Promise<RdapDomainRaw>;
        },
        {
          operation: 'rdap.checkAvailability',
          context: reqCtx,
          maxRetries: config.rdapMaxRetries,
          baseDelayMs: 1000,
          signal: ctx.signal,
          isTransient: (err: unknown) => {
            if (err instanceof Error) {
              const msg = err.message;
              // 404 is NOT transient — it's the availability signal
              if (msg.includes('404') || msg.includes('Not Found') || msg.includes('NotFound')) {
                return false;
              }
            }
            return true;
          },
        },
      );

      const record = normalizeDomain(raw);
      return { available: false, record };
    } catch (err) {
      // A 404 from the RDAP server means the domain is available (not registered)
      if (
        err instanceof Error &&
        (err.message.includes('404') ||
          err.message.includes('Not Found') ||
          err.message.includes('NotFound'))
      ) {
        return { available: true };
      }
      throw err;
    }
  }

  /** Look up an IP address or CIDR via RIR RDAP */
  async lookupIp(ip: string, ctx: Context): Promise<NormalizedIpNetwork> {
    const { valid, isIpv6 } = validateIp(ip);
    if (!valid) {
      throw validationError(`"${ip}" is not a valid IPv4, IPv6, or CIDR address.`, {
        reason: 'invalid_ip',
        ...ctx.recoveryFor('invalid_ip'),
      });
    }

    const base = ip.split('/')[0] ?? '';
    if (isPrivateIp(base)) {
      throw validationError(
        `"${base}" is a private or reserved IP address — no RIR RDAP record exists for it.`,
        {
          reason: 'private_range',
          ...ctx.recoveryFor('private_range'),
        },
      );
    }

    const rdapServer = await this.findIpRdapServer(ip, isIpv6, ctx);
    if (!rdapServer) {
      throw serviceUnavailable('No RIR RDAP server found for this IP address range.', { ip });
    }

    const config = getServerConfig();
    // IPv6 addresses contain colons which must NOT be percent-encoded in the RDAP path.
    // encodeURIComponent would produce 2001%3A4860%3A... which RDAP servers reject.
    const url = `${rdapServer}/ip/${base}`;
    const reqCtx = { requestId: ctx.requestId, tenantId: ctx.tenantId, timestamp: ctx.timestamp };

    const raw = await withRetry(
      async () => {
        const response = await fetchWithTimeout(url, config.rdapTimeoutMs, reqCtx, {
          headers: { Accept: 'application/rdap+json, application/json' },
          signal: ctx.signal,
        });
        return response.json() as Promise<RdapIpNetworkRaw>;
      },
      {
        operation: 'rdap.lookupIp',
        context: reqCtx,
        maxRetries: config.rdapMaxRetries,
        baseDelayMs: 1000,
        signal: ctx.signal,
      },
    );

    return normalizeIpNetwork(raw, ip);
  }

  /** Look up an ASN via RIR RDAP */
  async lookupAsn(asn: string, ctx: Context): Promise<NormalizedAsn> {
    const asnClean = asn.toUpperCase().replace(/^AS/, '');
    const asnNum = parseInt(asnClean, 10);
    if (Number.isNaN(asnNum) || asnNum <= 0) {
      throw validationError(
        `"${asn}" is not a valid ASN. Expected AS<number> or bare integer (e.g., AS15169 or 15169).`,
        {
          reason: 'invalid_asn',
          ...ctx.recoveryFor('invalid_asn'),
        },
      );
    }

    const rdapServer = await this.findAsnRdapServer(asnNum, ctx);
    if (!rdapServer) {
      throw notFound(`ASN ${asnNum} not found in any RIR RDAP server.`, {
        reason: 'asn_not_found',
        ...ctx.recoveryFor('asn_not_found'),
      });
    }

    const config = getServerConfig();
    const url = `${rdapServer}/autnum/${asnNum}`;
    const reqCtx = { requestId: ctx.requestId, tenantId: ctx.tenantId, timestamp: ctx.timestamp };

    const raw = await withRetry(
      async () => {
        const response = await fetchWithTimeout(url, config.rdapTimeoutMs, reqCtx, {
          headers: { Accept: 'application/rdap+json, application/json' },
          signal: ctx.signal,
        });
        return response.json() as Promise<RdapAutnumRaw>;
      },
      {
        operation: 'rdap.lookupAsn',
        context: reqCtx,
        maxRetries: config.rdapMaxRetries,
        baseDelayMs: 1000,
        signal: ctx.signal,
      },
    );

    return normalizeAutnum(raw, `AS${asnNum}`);
  }
}

// ─── Init/accessor pattern ────────────────────────────────────────────────────

let _service: RdapService | undefined;

export function initRdapService(_config: AppConfig, _storage: StorageService): void {
  _service = new RdapService();
}

export function getRdapService(): RdapService {
  if (!_service) {
    throw new Error('RdapService not initialized — call initRdapService() in setup()');
  }
  return _service;
}
