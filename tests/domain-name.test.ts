/**
 * @fileoverview Domain normalization behavior and CPU bounds.
 * @module tests/domain-name.test
 */

import { z } from '@cyanheads/mcp-ts-core';
import { describe, expect, it } from 'vitest';
import { normalizeDomainName } from '@/domain-name.js';
import { dnsNameInput, registrationNameInput } from '@/mcp-server/tools/definitions/_fqdn.js';

const maxName = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.');

describe('domain normalization (#40)', () => {
  it.each([
    ['MÜNCHEN。DE', 'registration', { domain: 'xn--mnchen-3ya.DE', unicode_domain: 'münchen.de' }],
    [
      'ｍüｎchen．de',
      'registration',
      { domain: 'xn--mnchen-3ya.de', unicode_domain: 'münchen.de' },
    ],
    ['пример｡рф', 'registration', { domain: 'xn--e1afmkfd.xn--p1ai', unicode_domain: 'пример.рф' }],
    ['127.1', 'registration', { domain: '127.1' }],
    ['１２７.１', 'registration', { domain: '127.1' }],
    ['Foo.Example.INVALID', 'registration', { domain: 'Foo.Example.INVALID' }],
    ['_DMARC.-edge-.Example.COM.', 'dns', { domain: '_DMARC.-edge-.Example.COM' }],
    [
      '_TXT.XN--BCHER-KVA.example｡',
      'dns',
      { domain: '_TXT.XN--BCHER-KVA.example', unicode_domain: '_TXT.bücher.example' },
    ],
    [
      `${'é'.repeat(57)}.com`,
      'registration',
      { domain: `xn--9c${'a'.repeat(57)}.com`, unicode_domain: `${'é'.repeat(57)}.com` },
    ],
    [maxName, 'registration', { domain: maxName }],
    [`${maxName}.`, 'dns', { domain: maxName }],
    [
      `bü${'\u00ad'.repeat(400)}cher.com`,
      'registration',
      { domain: 'xn--bcher-kva.com', unicode_domain: 'bücher.com' },
    ],
  ] as const)('normalizes %j in %s mode', (input, mode, expected) => {
    expect(normalizeDomainName(input, mode)).toEqual(expected);
  });

  it.each([
    'xn--a.com',
    'xn--.com',
    'example.com/path',
    'example.com?query',
    'example.com#fragment',
    'example.com\\path',
    'example.com:443',
    'user@example.com',
    '%65xample.com',
    'example..com',
    'example.com\n',
    'exam\tple.com',
    'exam\u0085ple.com',
    'exam\u0000ple.com',
    'exa\u00a0mple.com',
    'exämple／bad.com',
    'example',
    'example.com..',
    `${'é'.repeat(58)}.com`,
    `${maxName}d`,
    [...Array<string>(5).fill('é'.repeat(50)), 'com'].join('.'),
  ])('rejects %j in both modes', (input) => {
    expect(normalizeDomainName(input, 'registration')).toBeUndefined();
    expect(normalizeDomainName(input, 'dns')).toBeUndefined();
  });

  it.each(['-host.com', 'host-.com', '_dmarc.example.com', 'example.com.', 'example.com。'])(
    'rejects registration-only invalid spelling %j',
    (input) => {
      expect(normalizeDomainName(input, 'registration')).toBeUndefined();
      expect(normalizeDomainName(input, 'dns')).toBeDefined();
    },
  );

  it.each([registrationNameInput, dnsNameInput])('advertises lexical IDN support', (schema) => {
    const serialized = z.toJSONSchema(schema);
    const pattern = new RegExp(serialized.pattern as string);
    expect(pattern.test('münchen。de')).toBe(true);
    for (const invalid of ['example.com/path', 'example.com\n', '%65xample.com', 'example']) {
      expect(pattern.test(invalid)).toBe(false);
    }
  });
});

function cpuPerCall(fn: () => unknown, repetitions: number) {
  const start = process.threadCpuUsage();
  for (let i = 0; i < repetitions; i++) fn();
  const { user, system } = process.threadCpuUsage(start);
  return (user + system) / repetitions;
}

describe('domain normalization CPU bounds', () => {
  const patterns = [registrationNameInput, dnsNameInput].map(
    (schema) => new RegExp(z.toJSONSchema(schema).pattern as string),
  );
  it.each([
    ['digits', (size: number) => `${'1'.repeat(size)}.com`],
    ['trailing line break', (size: number) => `${'a.'.repeat(size / 2)}com\ny`],
    ['repeated line breaks', (size: number) => `x.${'  \r\n'.repeat(size / 4)}com`],
    ['Unicode', (size: number) => `a${'\u0301\u0323'.repeat(size / 2)}.com`],
    ['mapped Unicode', (size: number) => `bü${'\u00ad'.repeat(size)}cher.com`],
  ] as const)('bounds per-call thread CPU for %s', (_shape, input) => {
    const exercise = (value: string) => {
      for (const pattern of patterns) pattern.test(value);
      normalizeDomainName(value, 'registration');
      normalizeDomainName(value, 'dns');
    };
    const small = input(5000);
    for (let size = 10_000; size <= 320_000; size *= 2) {
      const large = input(size);
      let bestGrowth = Number.POSITIVE_INFINITY;
      let bestCpu = Number.POSITIVE_INFINITY;
      for (let sample = 0; sample < 3; sample++) {
        const baseline = cpuPerCall(() => exercise(small), 5);
        const cpu = cpuPerCall(() => exercise(large), 1);
        bestGrowth = Math.min(bestGrowth, cpu / Math.max(1, baseline));
        bestCpu = Math.min(bestCpu, cpu);
        if (cpu > 100_000) break;
      }
      expect(bestCpu).toBeLessThan(100_000);
      expect(bestGrowth).toBeLessThan(256);
    }
  });
});
