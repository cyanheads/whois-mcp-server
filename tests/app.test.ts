/**
 * @fileoverview Tests for the server's `createApp()` wiring — the session
 * posture it resolves to and the definitions it registers.
 * @module tests/app.test
 */

import type { ServerHandle } from '@cyanheads/mcp-ts-core';
import { createApp } from '@cyanheads/mcp-ts-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { appOptions } from '@/app.js';

describe('session posture', () => {
  let handle: ServerHandle | undefined;

  beforeEach(() => {
    // HTTP is the only transport MCP_SESSION_MODE applies to. Port 0 takes an
    // ephemeral port so the test never collides with a running server.
    vi.stubEnv('MCP_TRANSPORT_TYPE', 'http');
    vi.stubEnv('MCP_HTTP_PORT', '0');
    vi.stubEnv('MCP_HTTP_HOST', '127.0.0.1');
    vi.stubEnv('MCP_LOG_LEVEL', 'error');
  });

  afterEach(async () => {
    await handle?.shutdown('test');
    handle = undefined;
    vi.unstubAllEnvs();
  });

  it('resolves to stateless when the environment sets nothing', async () => {
    // An empty string reads as unset on the config path, so the declared
    // `sessionMode` — not the schema default `auto` — is what seeds the mode.
    vi.stubEnv('MCP_SESSION_MODE', '');

    handle = await createApp(appOptions);

    expect(handle.services.config.mcpSessionMode).toBe('stateless');
  });

  it('lets an explicit MCP_SESSION_MODE override the declared default', async () => {
    vi.stubEnv('MCP_SESSION_MODE', 'stateful');

    handle = await createApp(appOptions);

    // No `require: 'stateful'` is declared, so an operator can still pick the
    // other posture without startup refusing.
    expect(handle.services.config.mcpSessionMode).toBe('stateful');
  });
});

describe('appOptions', () => {
  it('registers every whois tool and no resources or prompts', () => {
    expect(appOptions.tools.map((t) => t.name)).toEqual([
      'whois_lookup_domain',
      'whois_check_availability',
      'whois_get_dns',
      'whois_lookup_ip',
      'whois_lookup_asn',
      'whois_get_dossier',
    ]);
    expect(appOptions.resources).toEqual([]);
    expect(appOptions.prompts).toEqual([]);
  });
});
