/**
 * @fileoverview Serializable identifier grammars shared by lookup schemas.
 * @module mcp-server/tools/definitions/_fqdn
 */

const HOST_LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
/** Registration hostname grammar, with exact end-of-input matching. */
export const REGISTRATION_NAME_PATTERN = new RegExp(
  `^${HOST_LABEL}(?:\\.${HOST_LABEL})+(?![\\s\\S])`,
);
/** DNS presentation-name grammar: underscore labels and one optional root dot. */
export const DNS_NAME_PATTERN =
  /^(?=[A-Za-z0-9_.-]{1,253}\.?(?![\s\S]))[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63})+\.?(?![\s\S])/;
/** Conservative IP/CIDR shape; complete address and prefix validity are semantic. */
export const IP_PATTERN = /^[0-9A-Fa-f:.]+(?:\/[0-9]+)?(?![\s\S])/;
/** Accepted ASN spelling, preserving padding, case and surrounding whitespace. */
export const ASN_PATTERN = /^\s*(?:[Aa][Ss]\s*)?\+?[0-9]+\s*(?![\s\S])/;
