/**
 * @fileoverview Validate and normalize registration hostnames and DNS owner names.
 * @module domain-name
 */

import { domainToASCII, domainToUnicode } from 'node:url';

const SEPARATOR = /[\u3002\uff0e\uff61]/g;
const ASCII = /^[A-Za-z0-9_-]+$/;
const RAW_LABEL = /^(?!.*\s)[A-Za-z0-9_\-\u00a0-\uffff]+(?![\s\S])/;
const NON_ASCII = /[^\u0020-\u007e]/;
const DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;
const IDNA_SUFFIX = '.invalid';
const MAX_LABEL_OCTETS = 63;
const MAX_DECOMPOSED_LABEL_LENGTH = MAX_LABEL_OCTETS * 4;

/** Keep only input that could fit a label after IDNA mapping and NFC. */
function prepareLongLabel(label: string): string | undefined {
  let significant = '';
  let count = 0;
  const ignored = new Map<string, boolean>();
  for (const point of label) {
    if (DEFAULT_IGNORABLE.test(point)) {
      // Retain whitespace for raw syntax validation and let the runtime decide
      // whether each other candidate disappears in IDNA mapping.
      const drops =
        ignored.get(point) ??
        (!/\s/.test(point) && domainToASCII(`a${point}${IDNA_SUFFIX}`) === `a${IDNA_SUFFIX}`);
      ignored.set(point, drops);
      if (drops) continue;
    }
    // Each encoded octet accounts for at most one NFC code point, whose
    // canonical decomposition is at most four code points.
    if (++count > MAX_DECOMPOSED_LABEL_LENGTH) return;
    significant += point;
  }
  return significant;
}

/** Normalize labels independently so numeric names retain their DNS spelling. */
export function normalizeDomainName(
  input: string,
  mode: 'registration' | 'dns',
): { domain: string; unicode_domain?: string } | undefined {
  let name = input.replace(SEPARATOR, '.');
  if (mode === 'dns' && name.endsWith('.')) name = name.slice(0, -1);
  // 128 nonempty labels and their separators cannot fit in 253 octets.
  const labels = name.split('.', 128);
  if (labels.length < 2 || labels.length === 128) return;

  const ascii: string[] = [];
  const display: string[] = [];
  let hasUnicode = false;
  let nameLength = labels.length - 1;
  for (const rawLabel of labels) {
    const label =
      rawLabel.length > MAX_DECOMPOSED_LABEL_LENGTH ? prepareLongLabel(rawLabel) : rawLabel;
    if (label === undefined || !RAW_LABEL.test(label)) return;
    const asciiInput = ASCII.test(label);
    const aceInput = label.slice(0, 4).toLowerCase() === 'xn--';
    let wire = label;
    if (!asciiInput || aceInput) {
      const encoded = domainToASCII(label + IDNA_SUFFIX);
      if (!encoded.endsWith(IDNA_SUFFIX)) return;
      const canonical = encoded.slice(0, -IDNA_SUFFIX.length);
      if (aceInput && canonical !== label.toLowerCase()) return;
      wire = asciiInput ? label : canonical;
    }

    nameLength += wire.length;
    if (wire.length > MAX_LABEL_OCTETS || nameLength > 253 || !ASCII.test(wire)) return;
    if (
      mode === 'registration' &&
      (wire.includes('_') || wire.startsWith('-') || wire.endsWith('-'))
    )
      return;

    ascii.push(wire);
    if (wire.slice(0, 4).toLowerCase() === 'xn--') {
      const canonical = wire.toLowerCase() + IDNA_SUFFIX;
      const decoded = domainToUnicode(canonical);
      if (!decoded.endsWith(IDNA_SUFFIX)) return;
      const uLabel = decoded.slice(0, -IDNA_SUFFIX.length);
      // Some runtimes echo undecodable ACE labels. A U-label must contain Unicode.
      if (
        !RAW_LABEL.test(uLabel) ||
        !NON_ASCII.test(uLabel) ||
        domainToASCII(decoded) !== canonical
      )
        return;
      display.push(uLabel);
      hasUnicode = true;
    } else {
      display.push(mode === 'registration' ? wire.toLowerCase() : wire);
    }
  }
  return { domain: ascii.join('.'), ...(hasUnicode ? { unicode_domain: display.join('.') } : {}) };
}
