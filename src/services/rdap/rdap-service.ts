/**
 * @fileoverview RDAP service — IANA bootstrap-driven domain, IP, and ASN lookups.
 * Caches the IANA bootstrap JSON for 24 hours to avoid a bootstrap hop on every query.
 * @module services/rdap/rdap-service
 */

import { isIP } from 'node:net';
import type { Context } from '@cyanheads/mcp-ts-core';
import type { AppConfig } from '@cyanheads/mcp-ts-core/config';
import {
  McpError,
  notFound,
  serviceUnavailable,
  validationError,
} from '@cyanheads/mcp-ts-core/errors';
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

/** Parsed lookup address; mapped IPv6 resolves through its embedded IPv4 address. */
type ParsedIp = { valid: true; base: string; value: bigint; isIpv6: boolean; hasCidr: boolean };

/** Parse a complete IP/CIDR token, retaining base-address lookup semantics. */
export function validateIp(ip: string): ParsedIp | { valid: false } {
  const [base = '', prefix, ...extra] = ip.split('/');
  const family = isIP(base);
  if (!family || base.includes('%') || extra.length > 0) return { valid: false };
  if (
    prefix !== undefined &&
    (!/^\d+$/.test(prefix) || Number(prefix) > (family === 6 ? 128 : 32))
  ) {
    return { valid: false };
  }
  const value = family === 6 ? ipv6ToBigInt(base) : ipv4ToBigInt(base);
  const mapped = family === 6 && value >> 32n === 0xffffn;
  const lookupValue = mapped ? value & 0xffffffffn : value;
  const lookupBase = mapped
    ? [24n, 16n, 8n, 0n].map((shift) => Number((lookupValue >> shift) & 255n)).join('.')
    : base;
  return {
    valid: true,
    base: lookupBase,
    value: lookupValue,
    isIpv6: family === 6 && !mapped,
    hasCidr: prefix !== undefined,
  };
}

/** Apply the server's explicit exclusions, not a blanket special-use policy. */
function isPrivateIp(ip: ParsedIp): boolean {
  if (ip.isIpv6) {
    return ip.value === 1n || ip.value >> 121n === 0x7en || ip.value >> 118n === 0x3fan;
  }
  const first = Number(ip.value >> 24n);
  const second = Number((ip.value >> 16n) & 255n);
  return (
    [0, 10, 127, 255].includes(first) ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

/** Convert a validated IPv4 address to its numeric value. */
function ipv4ToBigInt(ip: string): bigint {
  return ip.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
}

/** Build reverse PTR query name from an IPv4 address */
export function ipv4ToPtr(ip: string): string {
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

/** Expand a compressed IPv6 address to a full 128-bit BigInt */
function ipv6ToBigInt(ip: string): bigint {
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':');
    const tail = ipv4ToBigInt(ip.slice(lastColon + 1));
    ip = `${ip.slice(0, lastColon + 1)}${(tail >> 16n).toString(16)}:${(tail & 0xffffn).toString(16)}`;
  }
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
  const hex = ipv6ToBigInt(ip).toString(16).padStart(32, '0');
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

/** Identify RIR from an RDAP self-link URL */
function rirFromSelfLink(selfLink: string): string | undefined {
  const url = URL.parse(selfLink);
  if (!url) return;
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  for (const rir of ['arin', 'ripe', 'apnic', 'lacnic', 'afrinic']) {
    if (hostname === `${rir}.net` || hostname.endsWith(`.${rir}.net`)) return rir.toUpperCase();
  }
  return;
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
  const rdapSource = rirFromSelfLink(selfLink);

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
  const rir = rirFromSelfLink(selfLink);

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

/** True when the error is an RDAP 404 — the queried object does not exist upstream. */
function isRdapNotFound(err: unknown): boolean {
  return err instanceof McpError && err.data?.status === 404;
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
    const response = await fetchWithTimeout(url, config.rdapTimeoutMs, ctx, {
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
        const mask = prefixLen === 0 ? 0 : ~((1 << (32 - prefixLen)) - 1);
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

    try {
      const raw = await withRetry(
        async () => {
          const response = await fetchWithTimeout(url, config.rdapTimeoutMs, ctx, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: ctx.signal,
            expectedStatuses: [404],
          });
          return response.json() as Promise<RdapDomainRaw>;
        },
        {
          operation: 'rdap.lookupDomain',
          context: ctx,
          maxRetries: config.rdapMaxRetries,
          baseDelayMs: 1000,
          signal: ctx.signal,
          // 404 is NOT transient — domain is not registered; don't retry
          isTransient: (err: unknown) => !isRdapNotFound(err),
        },
      );
      return normalizeDomain(raw);
    } catch (err) {
      // RDAP 404 on a domain lookup means the domain is not registered
      if (isRdapNotFound(err)) {
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

    try {
      const raw = await withRetry(
        async () => {
          const response = await fetchWithTimeout(url, config.rdapTimeoutMs, ctx, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: ctx.signal,
            expectedStatuses: [404],
          });
          return response.json() as Promise<RdapDomainRaw>;
        },
        {
          operation: 'rdap.checkAvailability',
          context: ctx,
          maxRetries: config.rdapMaxRetries,
          baseDelayMs: 1000,
          signal: ctx.signal,
          // 404 is NOT transient — it's the availability signal
          isTransient: (err: unknown) => !isRdapNotFound(err),
        },
      );

      const record = normalizeDomain(raw);
      return { available: false, record };
    } catch (err) {
      // A 404 from the RDAP server means the domain is available (not registered)
      if (isRdapNotFound(err)) {
        return { available: true };
      }
      throw err;
    }
  }

  /** Look up an IP address or CIDR via RIR RDAP */
  async lookupIp(ip: string, ctx: Context): Promise<NormalizedIpNetwork> {
    const parsed = validateIp(ip);
    if (!parsed.valid) {
      throw validationError(`"${ip}" is not a valid IPv4, IPv6, or CIDR address.`, {
        reason: 'invalid_ip',
      });
    }

    const { base, isIpv6 } = parsed;
    if (isPrivateIp(parsed)) {
      throw validationError(
        `"${base}" is in an address range excluded by this server's lookup policy.`,
        {
          reason: 'private_range',
        },
      );
    }

    const rdapServer = await this.findIpRdapServer(base, isIpv6, ctx);
    if (!rdapServer) {
      throw serviceUnavailable('No RIR RDAP server found for this IP address range.', { ip });
    }

    const config = getServerConfig();
    // IPv6 addresses contain colons which must NOT be percent-encoded in the RDAP path.
    // encodeURIComponent would produce 2001%3A4860%3A... which RDAP servers reject.
    const url = `${rdapServer}/ip/${base}`;

    try {
      const raw = await withRetry(
        async () => {
          const response = await fetchWithTimeout(url, config.rdapTimeoutMs, ctx, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: ctx.signal,
            expectedStatuses: [404],
          });
          return response.json() as Promise<RdapIpNetworkRaw>;
        },
        {
          operation: 'rdap.lookupIp',
          context: ctx,
          maxRetries: config.rdapMaxRetries,
          baseDelayMs: 1000,
          signal: ctx.signal,
          // 404 is NOT transient — no netblock record exists; don't retry
          isTransient: (err: unknown) => !isRdapNotFound(err),
        },
      );

      return normalizeIpNetwork(raw, ip);
    } catch (err) {
      // RDAP 404 on an IP lookup means no netblock record exists upstream
      if (isRdapNotFound(err)) {
        throw notFound(`IP "${ip}" has no netblock record in RIR RDAP (404).`, {
          reason: 'ip_not_found',
          ...ctx.recoveryFor('ip_not_found'),
        });
      }
      throw err;
    }
  }

  /** Look up an ASN via RIR RDAP */
  async lookupAsn(asn: string, ctx: Context): Promise<NormalizedAsn> {
    const token = asn.trim();
    const match = /^(?:AS\s*)?\+?(\d+)$/i.exec(token);
    const asnNum = match ? Number(match[1]) : NaN;
    if (!Number.isInteger(asnNum) || asnNum < 1 || asnNum > 4294967295) {
      throw validationError(
        `"${asn}" is not a valid ASN. Expected a decimal integer from 1 to 4294967295, optionally prefixed with AS and a leading + (e.g., AS15169 or +15169).`,
        {
          reason: 'invalid_asn',
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

    try {
      const raw = await withRetry(
        async () => {
          const response = await fetchWithTimeout(url, config.rdapTimeoutMs, ctx, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: ctx.signal,
            expectedStatuses: [404],
          });
          return response.json() as Promise<RdapAutnumRaw>;
        },
        {
          operation: 'rdap.lookupAsn',
          context: ctx,
          maxRetries: config.rdapMaxRetries,
          baseDelayMs: 1000,
          signal: ctx.signal,
          // 404 is NOT transient — the ASN is not registered; don't retry
          isTransient: (err: unknown) => !isRdapNotFound(err),
        },
      );

      return normalizeAutnum(raw, `AS${asnNum}`);
    } catch (err) {
      // RDAP 404 on an ASN lookup means the ASN is not registered upstream
      if (isRdapNotFound(err)) {
        throw notFound(`ASN ${asnNum} not found (RDAP 404).`, {
          reason: 'asn_not_found',
          ...ctx.recoveryFor('asn_not_found'),
        });
      }
      throw err;
    }
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
