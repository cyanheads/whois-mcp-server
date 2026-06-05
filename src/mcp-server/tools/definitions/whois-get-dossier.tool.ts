/**
 * @fileoverview whois_get_dossier tool — one-call domain triage combining RDAP + DNS in parallel.
 * @module mcp-server/tools/definitions/whois-get-dossier.tool
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { getDohService } from '@/services/doh/doh-service.js';
import type { NormalizedDnsRecord } from '@/services/doh/types.js';
import { getRdapService } from '@/services/rdap/rdap-service.js';
import type { NormalizedDomain } from '@/services/rdap/types.js';
import { isValidFqdn } from './_fqdn.js';

/** True when the error is a typed domain_not_found from rdap-service */
function isDomainNotFound(err: unknown): boolean {
  return (
    err instanceof McpError &&
    typeof (err.data as Record<string, unknown>)?.reason === 'string' &&
    (err.data as Record<string, unknown>).reason === 'domain_not_found'
  );
}

/** Infer NS provider from the first NS record data (e.g., ns1.cloudflare.com → cloudflare) */
function inferNsProvider(nsRecords: NormalizedDnsRecord[]): string | undefined {
  if (nsRecords.length === 0) return;
  const ns = (nsRecords[0]?.data ?? '').toLowerCase().replace(/\.$/, '');
  // Common providers
  if (ns.includes('cloudflare')) return 'Cloudflare';
  if (ns.includes('awsdns') || ns.includes('amazonaws')) return 'AWS Route 53';
  if (ns.includes('google')) return 'Google Cloud DNS';
  if (ns.includes('azure-dns') || ns.includes('microsoftdns')) return 'Azure DNS';
  if (ns.includes('namebrightdns') || ns.includes('namebright')) return 'NameBright';
  if (ns.includes('nsone') || ns.includes('ns1.com')) return 'NS1';
  if (ns.includes('dnsimple')) return 'DNSimple';
  if (ns.includes('domaincontrol')) return 'GoDaddy';
  if (ns.includes('name.com')) return 'Name.com';
  if (ns.includes('registrar-servers')) return 'Namecheap';
  // Fall back to the second-level domain of the NS server
  const parts = ns.split('.');
  if (parts.length >= 2) return parts[parts.length - 2];
  return;
}

/** Infer MX provider from the first MX record data */
function inferMxProvider(mxRecords: NormalizedDnsRecord[]): string | undefined {
  if (mxRecords.length === 0) return;
  const mx = (mxRecords[0]?.data ?? '').toLowerCase().replace(/\.$/, '');
  if (mx.includes('google') || mx.includes('googlemail') || mx.includes('aspmx'))
    return 'Google Workspace';
  if (
    mx.includes('outlook') ||
    mx.includes('microsoft') ||
    mx.includes('office365') ||
    mx.includes('protection.outlook')
  )
    return 'Microsoft 365';
  if (mx.includes('mxroute')) return 'MXroute';
  if (mx.includes('mailchannels')) return 'MailChannels';
  if (mx.includes('amazonses') || mx.includes('amazonaws')) return 'Amazon SES';
  if (mx.includes('fastmail')) return 'Fastmail';
  if (mx.includes('protonmail')) return 'ProtonMail';
  if (mx.includes('zoho')) return 'Zoho Mail';
  if (mx.includes('sendgrid')) return 'SendGrid';
  if (mx.includes('mailgun')) return 'Mailgun';
  // Fall back to second-level domain
  const parts = mx.split('.');
  if (parts.length >= 2) return parts[parts.length - 2];
  return;
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
    'One-call domain triage: fetches registration record (RDAP) and DNS records (A, MX, NS, TXT) in ' +
    'parallel, returning a single normalized record with factual signals — domain age in days, ' +
    'privacy-redacted flag, registrar, NS provider inferred from NS records, mail provider inferred ' +
    'from MX records. No synthesized scores — factual signals only. Partial results are surfaced when ' +
    'one leg fails (registration or DNS marked with source_error); only when both legs fail does the ' +
    'tool throw both_legs_failed. For the full registration record use whois_lookup_domain. For DNS ' +
    'types beyond A/MX/NS/TXT (e.g., CNAME, CAA, SOA) use whois_get_dns.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },

  input: z.object({
    domain: z
      .string()
      .describe(
        'Fully qualified domain name for the triage (e.g., "github.com"). Must be a valid FQDN.',
      ),
  }),

  output: z.object({
    domain: z.string().describe('Normalized domain name.'),

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
        'True when the domain has a registration record. False = RDAP 404 (not registered). ' +
          'Null when RDAP leg failed.',
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
      .describe('True when delegation-signed. Null when RDAP leg unavailable.'),
    privacy_redacted: z
      .boolean()
      .nullable()
      .describe(
        'True when registrant contact info is privacy-redacted. Null when RDAP leg unavailable.',
      ),
    status: z.array(z.string()).describe('EPP status codes. Empty when RDAP leg failed.'),
    nameservers: z
      .array(z.string())
      .describe('Authoritative nameservers. Empty when RDAP leg failed.'),

    // DNS section
    a_records: z
      .array(z.string())
      .describe('IPv4 addresses (A records). Empty when DNS leg failed or NXDOMAIN.'),
    mx_records: z
      .array(z.string())
      .describe('Mail exchange hostnames (MX data). Empty when DNS leg failed or NXDOMAIN.'),
    ns_records: z
      .array(z.string())
      .describe('DNS nameservers from live DNS (NS data). Empty when DNS leg failed or NXDOMAIN.'),
    txt_records: z
      .array(z.string())
      .describe(
        'TXT record values (SPF, DKIM hints, etc.). Empty when DNS leg failed or NXDOMAIN.',
      ),
    dns_nxdomain: z
      .boolean()
      .nullable()
      .describe('True when DNS says domain does not exist (NXDOMAIN). Null when DNS leg failed.'),

    // Inferred signals
    ns_provider: z
      .string()
      .nullable()
      .describe(
        'DNS provider inferred from NS record (e.g., "Cloudflare", "AWS Route 53"). Null when unknown or DNS leg failed.',
      ),
    mx_provider: z
      .string()
      .nullable()
      .describe(
        'Mail provider inferred from MX record (e.g., "Google Workspace", "Microsoft 365"). Null when no MX or DNS leg failed.',
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
      reason: 'invalid_domain',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'Input is not a valid FQDN.',
      recovery:
        'Provide a valid fully-qualified domain name like "example.com" or "sub.example.org".',
    },
    {
      reason: 'both_legs_failed',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'Both RDAP and DoH legs failed — no data could be retrieved.',
      recovery:
        'Both RDAP and DNS services are unavailable. Retry in a few minutes or check network connectivity.',
    },
  ],

  async handler(input, ctx) {
    if (!isValidFqdn(input.domain)) {
      throw ctx.fail('invalid_domain', `"${input.domain}" is not a valid FQDN.`, {
        ...ctx.recoveryFor('invalid_domain'),
      });
    }

    ctx.log.info('Domain dossier lookup', { domain: input.domain });

    // Fan out RDAP and DNS lookups in parallel
    const [rdapSettled, dnsSettled] = await Promise.allSettled([
      getRdapService().lookupDomain(input.domain, ctx),
      getDohService().lookup(input.domain, ['A', 'MX', 'NS', 'TXT'], ctx),
    ]);

    const rdapOk = rdapSettled.status === 'fulfilled';
    const dnsOk = dnsSettled.status === 'fulfilled';
    // domain_not_found is a valid data signal (RDAP 404 = not registered), not a leg failure
    const rdapNotFound = rdapSettled.status === 'rejected' && isDomainNotFound(rdapSettled.reason);

    if (!rdapOk && !rdapNotFound && !dnsOk) {
      throw ctx.fail('both_legs_failed', 'Both RDAP and DNS lookups failed — no data available.', {
        rdap_error: rdapSettled.status === 'rejected' ? String(rdapSettled.reason) : undefined,
        dns_error: dnsSettled.status === 'rejected' ? String(dnsSettled.reason) : undefined,
        ...ctx.recoveryFor('both_legs_failed'),
      });
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

    // registered:
    //   true  — RDAP returned a record (domain exists)
    //   false — RDAP returned 404 (domain_not_found = not registered)
    //   null  — RDAP leg errored for another reason, or rdap_coverage: false
    const registered: boolean | null = rdapNotFound
      ? false
      : rdapOk && reg
        ? reg.rdap_coverage
          ? true
          : null
        : null;

    return {
      domain: input.domain.toLowerCase(),
      // rdapNotFound means RDAP server was reachable (coverage: true) but domain doesn't exist
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
      mx_records: mxRecords.map((r) => r.data.replace(/\.$/, '')),
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

    // Registration section
    lines.push('\n## Registration');
    if (result.rdap_coverage === null) {
      lines.push(`**RDAP:** Failed`);
    } else if (!result.rdap_coverage) {
      lines.push('**RDAP Coverage:** None — TLD has no RDAP server');
    } else {
      lines.push(
        `**Registered:** ${result.registered ? 'Yes' : result.registered === false ? 'No' : 'Unknown'}`,
      );
      if (result.created_date) lines.push(`**Created:** ${result.created_date}`);
      if (result.expiry_date) lines.push(`**Expires:** ${result.expiry_date}`);
      if (result.age_days !== null) lines.push(`**Age:** ${result.age_days} days`);
      lines.push(
        `**DNSSEC:** ${result.dnssec_signed ? 'Signed' : result.dnssec_signed === false ? 'Not signed' : 'Unknown'}`,
      );
      lines.push(
        `**Privacy Redacted:** ${result.privacy_redacted ? 'Yes' : result.privacy_redacted === false ? 'No' : 'Unknown'}`,
      );
      if (result.status.length > 0) lines.push(`**Status:** ${result.status.join(', ')}`);
      if (result.nameservers.length > 0)
        lines.push(`**Nameservers (RDAP):** ${result.nameservers.join(', ')}`);
    }
    if (result.registrar) lines.push(`**Registrar:** ${result.registrar}`);
    if (result.rdap_source_error) lines.push(`**RDAP Error:** ${result.rdap_source_error}`);

    // DNS section
    lines.push('\n## DNS');
    if (result.dns_source_error) {
      lines.push(`**DNS:** Failed — ${result.dns_source_error}`);
    } else if (result.dns_nxdomain) {
      lines.push('**NXDOMAIN:** Domain does not exist in DNS.');
    }
    if (result.a_records.length > 0) lines.push(`**A:** ${result.a_records.join(', ')}`);
    if (result.ns_records.length > 0) lines.push(`**NS:** ${result.ns_records.join(', ')}`);
    if (result.mx_records.length > 0) lines.push(`**MX:** ${result.mx_records.join(', ')}`);
    if (result.txt_records.length > 0) {
      // TXT records are attacker-controlled free-text; backtick-fence each value to prevent prompt injection
      const fenced = result.txt_records.slice(0, 3).map((v) => `\`${v}\``);
      lines.push(`**TXT:** ${fenced.join(' | ')}`);
    }

    // Inferred signals
    lines.push('\n## Signals');
    lines.push(`**NS Provider:** ${result.ns_provider ?? 'Unknown'}`);
    lines.push(`**Mail Provider:** ${result.mx_provider ?? 'None / Unknown'}`);

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
