/**
 * @fileoverview Full-exchange routing deadline, failure and cancellation tests at HTTP boundary.
 * @module tests/services/routing-service.test
 */
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { whoisLookupIp } from '@/mcp-server/tools/definitions/whois-lookup-ip.tool.js';
import { RoutingService } from '@/services/routing/routing-service.js';
import { textOf, upstream } from '../helpers/upstream.js';

let http: ReturnType<typeof upstream>;
afterEach(() => {
  http?.restore();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('routing HTTP exchange', () => {
  it.each([400, 429, 503])('discloses HTTP %s once, without retries', async (status) => {
    http = upstream({ routing: () => new Response(null, { status }) });
    expect(await new RoutingService().lookup('8.8.8.8', createMockContext())).toMatchObject({
      status: 'failed',
      source_error: expect.any(String),
      recovery: expect.any(String),
    });
    expect(http.calls).toHaveLength(1);
  });
  it.each(['headers', 'body'] as const)(
    'bounds stalled %s under one 3000 ms deadline',
    async (stage) => {
      vi.useFakeTimers();
      const started = Promise.withResolvers<void>();
      let body: ReadableStreamDefaultController<Uint8Array> | undefined;
      http = upstream({
        routing: () => {
          started.resolve();
          if (stage === 'headers') return new Promise<Response>(() => {});
          return new Response(
            new ReadableStream<Uint8Array>({
              start(controller) {
                body = controller;
                controller.enqueue(new TextEncoder().encode('{'));
              },
            }),
          );
        },
      });
      const pending = new RoutingService().lookup('8.8.8.8', createMockContext());
      await started.promise;
      await vi.advanceTimersByTimeAsync(2999);
      let settled = false;
      void pending.then(() => {
        settled = true;
      });
      await Promise.resolve();
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(await pending).toMatchObject({
        status: 'failed',
        source_error: expect.stringMatching(/deadline|timeout/i),
      });
      expect(http.calls).toHaveLength(1);
      expect(http.calls[0]!.request.signal.aborted).toBe(true);
      body?.close();
    },
  );
  it.each(['headers', 'body'] as const)(
    'propagates caller cancellation during %s through both contract surfaces',
    async (stage) => {
      const controller = new AbortController();
      const started = Promise.withResolvers<void>();
      let body: ReadableStreamDefaultController<Uint8Array> | undefined;
      http = upstream({
        routing: () => {
          if (stage === 'headers') {
            started.resolve();
            return new Promise<Response>(() => {});
          }
          return new Response(
            new ReadableStream<Uint8Array>({
              start(stream) {
                body = stream;
                stream.enqueue(new TextEncoder().encode('{'));
                started.resolve();
              },
            }),
          );
        },
      });
      const pending = runToolContract(
        whoisLookupIp,
        { ip: '8.8.8.8', include_routing: true },
        { context: { signal: controller.signal } },
      );
      await started.promise;
      controller.abort();
      const result = await pending;
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({ error: { code: -32011 } });
      expect(textOf(result)).toMatch(/cancel|abort/i);
      expect(
        http.calls.filter((call) => new URL(call.request.url).hostname === 'stat.ripe.net'),
      ).toHaveLength(1);
      body?.close();
    },
  );
});
