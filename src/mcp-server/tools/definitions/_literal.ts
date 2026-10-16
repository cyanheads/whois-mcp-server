/**
 * @fileoverview Literal provider values for Markdown presentation without whitespace normalization.
 * @module mcp-server/tools/definitions/_literal
 */

/** Keep ordinary text compact; fence values whose punctuation or spacing Markdown can reinterpret. */
export function literal(value: string): string {
  let needsFence = value.length === 0;
  let run = 0;
  let longestRun = 0;
  for (let index = 0; index < value.length; index++) {
    const char = value.charAt(index);
    run = char === '`' ? run + 1 : 0;
    longestRun = Math.max(longestRun, run);
    if (
      '`\\*_[]<>|&~'.includes(char) ||
      char === '\n' ||
      char === '\r' ||
      char === '\t' ||
      (char === ' ' && (index === 0 || index === value.length - 1 || value[index - 1] === ' '))
    )
      needsFence = true;
  }
  if (!needsFence) return value;
  const fence = '`'.repeat(Math.max(3, longestRun + 1));
  return `\n${fence}\n${value}\n${fence}\n`;
}
