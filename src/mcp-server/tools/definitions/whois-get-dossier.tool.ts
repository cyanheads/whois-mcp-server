/**
 * @fileoverview whois_get_dossier tool — one-call domain triage combining RDAP + DNS in parallel.
 * @module mcp-server/tools/definitions/whois-get-dossier.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { parse } from 'tldts';
import { getDohService } from '@/services/doh/doh-service.js';
import type { NormalizedDnsRecord } from '@/services/doh/types.js';
import {
  getRdapService,
  icannRegistrableParent,
  isDomainNotFound,
} from '@/services/rdap/rdap-service.js';
import type { NormalizedDomain } from '@/services/rdap/types.js';
import { registrationNameInput, requireDomainName, unicodeDomainOutput } from './_fqdn.js';
import { literal } from './_literal.js';

/** Infer NS provider from the first NS record data (e.g., ns1.cloudflare.com → cloudflare) */
function inferNsProvider(nsRecords: NormalizedDnsRecord[]): string | undefined {
  if (nsRecords.length === 0) return;
  const ns = (nsRecords[0]?.data ?? '').toLowerCase().replace(/\.$/, '');
  // Common providers
  if (hasDomain(ns, 'cloudflare.com')) return 'Cloudflare';
  if (/(^|\.)awsdns-\d+\.(com|net|org|co\.uk)$/.test(ns) || hasDomain(ns, 'amazonaws.com'))
    return 'AWS Route 53';
  if (hasDomain(ns, 'google.com', 'googledomains.com')) return 'Google Cloud DNS';
  if (
    hasDomain(
      ns,
      'azure-dns.com',
      'azure-dns.net',
      'azure-dns.org',
      'azure-dns.info',
      'microsoftdns.com',
    )
  )
    return 'Azure DNS';
  if (hasDomain(ns, 'namebrightdns.com', 'namebright.com')) return 'NameBright';
  if (hasDomain(ns, 'nsone.net', 'ns1.com')) return 'NS1';
  if (hasDomain(ns, 'dnsimple.com')) return 'DNSimple';
  if (hasDomain(ns, 'domaincontrol.com')) return 'GoDaddy';
  if (hasDomain(ns, 'name.com')) return 'Name.com';
  if (hasDomain(ns, 'registrar-servers.com')) return 'Namecheap';
  return providerLabel(ns);
}

/** Infer MX provider from the first MX record data */
function inferMxProvider(mxRecords: NormalizedDnsRecord[]): string | undefined {
  if (mxRecords.length === 0) return;
  const mx = (mxRecords[0]?.data ?? '')
    .trim()
    .replace(/^\d+\s+/, '')
    .toLowerCase()
    .replace(/\.$/, '');
  if (hasDomain(mx, 'google.com', 'googlemail.com')) return 'Google Workspace';
  if (hasDomain(mx, 'outlook.com', 'microsoft.com', 'office365.com')) return 'Microsoft 365';
  if (hasDomain(mx, 'mxroute.com')) return 'MXroute';
  if (hasDomain(mx, 'mailchannels.net')) return 'MailChannels';
  if (hasDomain(mx, 'amazonses.com', 'amazonaws.com')) return 'Amazon SES';
  if (hasDomain(mx, 'fastmail.com', 'messagingengine.com')) return 'Fastmail';
  if (hasDomain(mx, 'protonmail.com', 'protonmail.ch')) return 'ProtonMail';
  if (hasDomain(mx, 'zoho.com')) return 'Zoho Mail';
  if (hasDomain(mx, 'sendgrid.net')) return 'SendGrid';
  if (hasDomain(mx, 'mailgun.org')) return 'Mailgun';
  return providerLabel(mx);
}

/** Infer a label from the hostname when a known provider does not match. */
function providerLabel(hostname: string): string | undefined {
  const suffix = parse(hostname, { allowPrivateDomains: false });
  if (suffix.isIcann) return suffix.domainWithoutSuffix ?? undefined;
  return hostname.split('.').at(-2);
}

/** Match whole DNS domains, including their subdomains. */
function hasDomain(hostname: string, ...domains: string[]): boolean {
  return domains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

/** Compute domain age in days from creation date string */
function ageDaysFromCreated(createdDate: string | undefined): number | undefined {
  if (!createdDate) return;
  const created = new Date(createdDate);
  if (Number.isNaN(created.getTime())) return;
  const diffMs = Date.now() - created.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

export const whoisGetDossier = tool('whois_get_dossier', {
  title: 'Domain Dossier',
  description:
    'Fetch the exact registration record and A, MX, NS and TXT records in parallel. After an exact registry 404, check the ICANN registrable parent when one is known and identify it as registration_domain. DNS stays on the supplied name. Returns registrar, domain age, privacy evidence and inferred NS and mail providers. A failed source leaves partial results when the other source succeeds. Use whois_lookup_domain for full registration details or whois_get_dns for additional record types.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    domain: registrationNameInput,
  }),

  output: z.object({
    domain: z.string().describe('Lowercase ASCII domain used for DNS.'),
    unicode_domain: unicodeDomainOutput,
    registration_domain: z
      .string()
      .optional()
      .describe(
        'ICANN registrable parent queried for registration after an exact 404. Omitted when registration was queried only for domain.',
      ),

    // Registration section
    rdap_coverage: z
      .boolean()
      .nullable()
      .describe(
        'True = RDAP server found. False = no RDAP coverage. Null = RDAP leg failed (source_error set).',
      ),
    registered: z
      .boolean()
      .nullable()
      .describe(
        'True when a registration record was found for registration_domain or, when omitted, domain. False means the registration query returned 404. Null means coverage was absent or the query failed.',
      ),
    registrar: z.string().optional().describe('Registrar name from registration record.'),
    created_date: z.string().optional().describe('ISO 8601 registration creation date.'),
    expiry_date: z.string().optional().describe('ISO 8601 registration expiry date.'),
    age_days: z
      .number()
      .nullable()
      .describe('Domain age in days since creation_date. Null when created_date is unavailable.'),
    dnssec_signed: z
      .boolean()
      .nullable()
      .describe('Provider delegationSigned value; null when evidence or RDAP coverage is absent.'),
    privacy_redacted: z
      .boolean()
      .nullable()
      .describe(
        'True for explicit registrant redaction evidence; null when evidence or RDAP coverage is absent.',
      ),
    status: z.array(z.string()).describe('EPP status codes. Empty when RDAP leg failed.'),
    nameservers: z
      .array(z.string())
      .describe('Authoritative nameservers. Empty when RDAP leg failed.'),

    // DNS section
    a_records: z
      .array(z.string())
      .describe('IPv4 addresses (A records). Empty when DNS failed or no A answers were returned.'),
    mx_records: z
      .array(z.string())
      .describe(
        'Mail exchange data; 0 . explicitly means no mail service. Empty when no MX evidence is returned.',
      ),
    ns_records: z
      .array(z.string())
      .describe(
        'DNS nameservers from live DNS (NS data). Empty when DNS failed or no NS answers were returned.',
      ),
    txt_records: z
      .array(z.string())
      .describe(
        'TXT record values (SPF, DKIM hints, etc.). Empty when DNS failed or no TXT answers were returned.',
      ),
    dns_nxdomain: z
      .boolean()
      .nullable()
      .describe('True when at least one DNS query returned NXDOMAIN. Null when DNS leg failed.'),

    // Inferred signals
    ns_provider: z
      .string()
      .nullable()
      .describe(
        'Provider inferred from the first NS target by a known hostname match or registrable label. Null when unknown or DNS failed.',
      ),
    mx_provider: z
      .string()
      .nullable()
      .describe(
        'Provider inferred from the first MX target by a known hostname match or registrable label. Null when unknown, null MX, or DNS failed.',
      ),

    // Error signals
    rdap_source_error: z
      .string()
      .optional()
      .describe('Error message from the RDAP leg when it failed. Omitted on success.'),
    dns_source_error: z
      .string()
      .optional()
      .describe('Error message from the DNS leg when it failed. Omitted on success.'),
  }),

  errors: [
    {
      reason: 'both_legs_failed',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'Both RDAP and DoH legs failed — no data could be retrieved.',
      recovery:
        'Both RDAP and DNS services are unavailable. Retry in a few minutes or check network connectivity.',
    },
  ],

  async handler(input, ctx) {
    const normalized = requireDomainName(input.domain, 'registration');
    const domain = normalized.domain.toLowerCase();
    ctx.log.info('Domain dossier lookup', { domain });

    const rdap = getRdapService();
    let registrationDomain: string | undefined;
    // Parent fallback shares a total budget; exact lookup retains its configured deadline.
    const rdapCtx = { ...ctx, signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(45_000)]) };
    const [rdapSettled, dnsSettled] = await Promise.allSettled([
      rdap.lookupDomain(normalized.domain, ctx).catch((error: unknown) => {
        ctx.signal.throwIfAborted();
        if (!isDomainNotFound(error)) throw error;
        const parent = icannRegistrableParent(domain);
        if (!parent || rdapCtx.signal.aborted) throw error;
        registrationDomain = parent;
        return rdap.lookupDomain(parent, rdapCtx);
      }),
      getDohService().lookup(normalized.domain, ['A', 'MX', 'NS', 'TXT'], ctx),
    ]);
    ctx.signal.throwIfAborted();

    const rdapOk = rdapSettled.status === 'fulfilled';
    const dnsOk = dnsSettled.status === 'fulfilled';
    // A missing registry object is data, not a failed RDAP leg.
    const rdapNotFound = rdapSettled.status === 'rejected' && isDomainNotFound(rdapSettled.reason);

    if (!rdapOk && !rdapNotFound && !dnsOk) {
      throw ctx.fail(
        'both_legs_failed',
        registrationDomain
          ? `RDAP lookup for "${registrationDomain}" and DNS lookup for "${domain}" both failed.`
          : 'Both RDAP and DNS lookups failed — no data available.',
        {
          ...(registrationDomain ? { registration_domain: registrationDomain } : {}),
          rdap_error: rdapSettled.status === 'rejected' ? String(rdapSettled.reason) : undefined,
          dns_error: dnsSettled.status === 'rejected' ? String(dnsSettled.reason) : undefined,
        },
      );
    }

    // Build result from available legs
    let reg: NormalizedDomain | undefined;
    let rdapSourceError: string | undefined;

    if (rdapOk) {
      reg = rdapSettled.value;
    } else if (!rdapNotFound) {
      rdapSourceError =
        rdapSettled.reason instanceof Error
          ? rdapSettled.reason.message
          : String(rdapSettled.reason);
    }

    let dnsRecords: NormalizedDnsRecord[] = [];
    let dnsNxdomain: boolean | null = null;
    let dnsSourceError: string | undefined;

    if (dnsOk) {
      dnsRecords = dnsSettled.value.records;
      dnsNxdomain = dnsSettled.value.nxdomain;
    } else {
      dnsSourceError =
        dnsSettled.reason instanceof Error ? dnsSettled.reason.message : String(dnsSettled.reason);
    }

    const nsRecords = dnsRecords.filter((r) => r.type === 'NS');
    const mxRecords = dnsRecords.filter((r) => r.type === 'MX');
    const aRecords = dnsRecords.filter((r) => r.type === 'A');
    const txtRecords = dnsRecords.filter((r) => r.type === 'TXT');

    const ageDays = reg ? (ageDaysFromCreated(reg.created_date) ?? null) : null;
    const nsProvider = dnsOk ? (inferNsProvider(nsRecords) ?? null) : null;
    const mxProvider = dnsOk ? (inferMxProvider(mxRecords) ?? null) : null;

    /**
     * Preserve the registered field as registry-record presence:
     * true for a record, false for RDAP 404, null for absent coverage or failure.
     */
    const registered: boolean | null = rdapNotFound
      ? false
      : rdapOk && reg
        ? reg.rdap_coverage
          ? true
          : null
        : null;

    return {
      ...normalized,
      domain,
      ...(registrationDomain ? { registration_domain: registrationDomain } : {}),
      // RDAP 404 proves coverage, but only establishes registry-record absence.
      rdap_coverage: rdapNotFound ? true : rdapOk ? (reg?.rdap_coverage ?? null) : null,
      registered,
      registrar: reg?.registrar,
      created_date: reg?.created_date,
      expiry_date: reg?.expiry_date,
      age_days: ageDays,
      dnssec_signed: rdapOk ? (reg?.dnssec_signed ?? null) : null,
      privacy_redacted: rdapOk ? (reg?.registrant_redacted ?? null) : null,
      status: reg?.status ?? [],
      nameservers: reg?.nameservers ?? [],
      a_records: aRecords.map((r) => r.data),
      mx_records: mxRecords.map((r) =>
        r.data.trim() === '0 .' ? r.data : r.data.replace(/\.$/, ''),
      ),
      ns_records: nsRecords.map((r) => r.data.replace(/\.$/, '')),
      txt_records: txtRecords.map((r) => r.data),
      dns_nxdomain: dnsNxdomain,
      ns_provider: nsProvider,
      mx_provider: mxProvider,
      ...(rdapSourceError ? { rdap_source_error: rdapSourceError } : {}),
      ...(dnsSourceError ? { dns_source_error: dnsSourceError } : {}),
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`# Domain Dossier: ${result.domain}`);
    if (result.unicode_domain) lines.push(`**Unicode Display:** ${literal(result.unicode_domain)}`);

    // Registration section
    lines.push('\n## Registration');
    if (result.registration_domain)
      lines.push(`**Registration Domain:** ${literal(result.registration_domain)}`);
    lines.push(
      `**Registered (RDAP record):** ${result.registered === true ? 'Found' : result.registered === false ? 'Not found' : 'Unknown'}`,
    );
    if (result.rdap_coverage === null) {
      lines.push(`**RDAP:** Failed`);
    } else if (!result.rdap_coverage) {
      lines.push('**RDAP Coverage:** None — TLD has no RDAP server');
    } else {
      if (result.created_date) lines.push(`**Created:** ${literal(result.created_date)}`);
      if (result.expiry_date) lines.push(`**Expires:** ${literal(result.expiry_date)}`);
      if (result.age_days !== null) lines.push(`**Age:** ${result.age_days} days`);
      lines.push(
        `**DNSSEC:** ${result.dnssec_signed ? 'Signed' : result.dnssec_signed === false ? 'Not signed' : 'Unknown'}`,
      );
      lines.push(
        `**Privacy Redacted:** ${result.privacy_redacted ? 'Yes' : result.privacy_redacted === false ? 'No' : 'Unknown'}`,
      );
      if (result.status.length > 0)
        lines.push(`**Status:** ${result.status.map(literal).join(', ')}`);
      if (result.nameservers.length > 0)
        lines.push(`**Nameservers (RDAP):** ${result.nameservers.map(literal).join(', ')}`);
    }
    if (result.registrar) lines.push(`**Registrar:** ${literal(result.registrar)}`);
    if (result.rdap_coverage !== true) {
      lines.push('**DNSSEC:** Unknown', '**Privacy Redacted:** Unknown');
    }
    if (result.rdap_source_error)
      lines.push(`**RDAP Error:** ${literal(result.rdap_source_error)}`);

    // DNS section
    lines.push('\n## DNS');
    if (result.dns_source_error) {
      lines.push(`**DNS:** Failed — ${literal(result.dns_source_error)}`);
    } else if (result.dns_nxdomain) {
      lines.push('**NXDOMAIN:** At least one DNS query returned NXDOMAIN.');
    }
    if (result.a_records.length > 0)
      lines.push(`**A:** ${result.a_records.map(literal).join(', ')}`);
    if (result.ns_records.length > 0)
      lines.push(`**NS:** ${result.ns_records.map(literal).join(', ')}`);
    if (result.mx_records.length > 0)
      lines.push(`**MX:** ${result.mx_records.map(literal).join(', ')}`);
    if (result.mx_records.some((value) => value.trim() === '0 .'))
      lines.push('**Null MX:** The domain explicitly accepts no mail.');
    if (result.txt_records.length > 0) {
      lines.push('**TXT:**');
      // Longer fences preserve literal data; delimiters are presentation, not a security boundary.
      for (const value of result.txt_records) {
        let longestRun = 0;
        for (const run of value.matchAll(/`+/g)) longestRun = Math.max(longestRun, run[0].length);
        const fence = '`'.repeat(Math.max(3, longestRun + 1));
        lines.push(`${fence}\n${value}\n${fence}`);
      }
    }

    // Inferred signals
    lines.push('\n## Signals');
    lines.push(`**NS Provider:** ${literal(result.ns_provider ?? 'Unknown')}`);
    lines.push(`**Mail Provider:** ${literal(result.mx_provider ?? 'None / Unknown')}`);

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
