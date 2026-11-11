/**
 * @fileoverview Serializable identifier grammars shared by lookup schemas.
 * @module mcp-server/tools/definitions/_fqdn
 */

import { z } from '@cyanheads/mcp-ts-core';
import { invalidParams } from '@cyanheads/mcp-ts-core/errors';
import { normalizeDomainName } from '@/domain-name.js';

const DOT = '[.\\u3002\\uff0e\\uff61]';
// Exclude the Unicode dot variants from label characters so the first label has one boundary.
const LETTER = 'A-Za-z0-9\\u00a0-\\u3001\\u3003-\\uff0d\\uff0f-\\uff60\\uff62-\\uffff';
const REGISTRATION_PATTERN = new RegExp(
  `^(?![^\\s]*\\s)[${LETTER}][${LETTER}-]*${DOT}[${LETTER}.\\u3002\\uff0e\\uff61-]*[${LETTER}](?![\\s\\S])`,
);
const DNS_PATTERN = new RegExp(
  `^(?![^\\s]*\\s)[${LETTER}_-]+${DOT}[${LETTER}_.\\u3002\\uff0e\\uff61-]*[${LETTER}_-]${DOT}?(?![\\s\\S])`,
);

const REGISTRATION_GUIDANCE =
  'Provide an ASCII or Unicode hostname such as example.com or bücher.com. Registration labels cannot contain underscores, edge hyphens or a root dot.';
const DNS_GUIDANCE =
  'Provide an ASCII or Unicode DNS owner such as _dmarc.example.com. Underscores and one terminal root dot are allowed.';

/** Advertise lexical constraints and validate normalized octet bounds in the handler. */
export const registrationNameInput = z
  .string()
  .regex(REGISTRATION_PATTERN, REGISTRATION_GUIDANCE)
  .describe(REGISTRATION_GUIDANCE);

/** Advertise the separate DNS owner grammar. */
export const dnsNameInput = z.string().regex(DNS_PATTERN, DNS_GUIDANCE).describe(DNS_GUIDANCE);

/** Decode display consistently across all domain tool outputs. */
export const unicodeDomainOutput = z
  .string()
  .optional()
  .describe('IDNA-decoded display of domain when it differs from the ASCII name.');

/** Validate the tool argument before dispatch and preserve the invalid_arguments contract. */
export function requireDomainName(input: string, mode: 'registration' | 'dns') {
  const name = normalizeDomainName(input, mode);
  if (name) return name;
  const guidance = mode === 'registration' ? REGISTRATION_GUIDANCE : DNS_GUIDANCE;
  throw invalidParams('Invalid domain name.', {
    reason: 'invalid_arguments',
    recovery: {
      hint: `domain: ${guidance} Use at most 63 ASCII octets per normalized label and 253 per normalized name.`,
    },
  });
}
/** Conservative IP/CIDR shape; complete address and prefix validity are semantic. */
export const IP_PATTERN = /^[0-9A-Fa-f:.]+(?:\/[0-9]+)?(?![\s\S])/;
/** Accepted ASN spelling, preserving padding, case and surrounding whitespace. */
export const ASN_PATTERN = /^\s*(?:[Aa][Ss]\s*)?\+?[0-9]+\s*(?![\s\S])/;
