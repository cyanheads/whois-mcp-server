/**
 * @fileoverview Shared FQDN validation used across tool handlers.
 * @module mcp-server/tools/definitions/_fqdn
 */

/** Simple FQDN validation: labels separated by dots, no consecutive dots, length limits */
export function isValidFqdn(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  const labels = domain.split('.');
  if (labels.length < 2) return false;
  return labels.every((label) => {
    if (!label || label.length > 63) return false;
    return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$/.test(label);
  });
}
