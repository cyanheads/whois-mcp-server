/**
 * @fileoverview RDAP service domain types — raw upstream shapes and normalized outputs.
 * @module services/rdap/types
 */

// ─── Raw RDAP upstream types ─────────────────────────────────────────────────

/** vCard array as returned by RDAP (RFC 6350 format) */
export type VCard = [string, unknown][];

/** Raw RDAP entity object */
export interface RdapEntity {
  entities?: RdapEntity[];
  handle?: string;
  objectClassName?: string;
  publicIds?: Array<{ type: string; identifier: string }>;
  roles?: string[];
  vcardArray?: ['vcard', VCard];
}

/** Raw RDAP event object */
export interface RdapEvent {
  eventAction: string;
  eventDate: string;
}

/** Raw RDAP nameserver object */
export interface RdapNameserver {
  ldhName?: string;
  unicodeName?: string;
}

/** Raw RDAP link object */
export interface RdapLink {
  href?: string;
  rel?: string;
  type?: string;
}

/** Raw RDAP domain response */
export interface RdapDomainRaw {
  entities?: RdapEntity[];
  events?: RdapEvent[];
  handle?: string;
  ldhName?: string;
  links?: RdapLink[];
  nameservers?: RdapNameserver[];
  objectClassName?: string;
  port43?: string;
  remarks?: Array<{ description: string[] }>;
  secureDNS?: {
    delegationSigned?: boolean;
    zoneSigned?: boolean;
  };
  status?: string[];
  unicodeName?: string;
}

/** Raw RDAP IP network response */
export interface RdapIpNetworkRaw {
  cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>;
  country?: string;
  endAddress?: string;
  entities?: RdapEntity[];
  events?: RdapEvent[];
  handle?: string;
  ipVersion?: string;
  links?: RdapLink[];
  name?: string;
  objectClassName?: string;
  parentHandle?: string;
  startAddress?: string;
  type?: string;
}

/** Raw RDAP autnum (ASN) response */
export interface RdapAutnumRaw {
  country?: string;
  endAutnum?: number;
  entities?: RdapEntity[];
  events?: RdapEvent[];
  handle?: string;
  links?: RdapLink[];
  name?: string;
  objectClassName?: string;
  startAutnum?: number;
  type?: string;
}

// ─── IANA Bootstrap types ─────────────────────────────────────────────────────

/** IANA Bootstrap JSON format */
export interface IanaBootstrap {
  publication: string;
  services: Array<[string[], string[]]>;
  version: string;
}

// ─── Normalized output types ──────────────────────────────────────────────────

/** Normalized domain registration record */
export interface NormalizedDomain {
  created_date?: string;
  dnssec_signed: boolean;
  domain: string;
  expiry_date?: string;
  handle?: string;
  nameservers: string[];
  rdap_coverage: boolean;
  rdap_last_updated?: string;
  registrant_org?: string;
  registrant_redacted: boolean;
  registrar?: string;
  registrar_iana_id?: string;
  status: string[];
  updated_date?: string;
}

/** Normalized IP network record */
export interface NormalizedIpNetwork {
  abuse_email?: string;
  cidr?: string;
  country?: string;
  end_address?: string;
  handle?: string;
  ip: string;
  ip_version?: string;
  name?: string;
  org_name?: string;
  /** Reverse DNS hostname, null when PTR lookup fails or returns nothing. */
  ptr: string | null;
  rdap_source?: string;
  start_address?: string;
  type?: string;
}

/** Normalized ASN record */
export interface NormalizedAsn {
  asn: string;
  country?: string;
  end_autnum?: number;
  handle?: string;
  name?: string;
  org_name?: string;
  rir?: string;
  start_autnum?: number;
  type?: string;
}
