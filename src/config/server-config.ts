/**
 * @fileoverview Server-specific environment configuration for whois-mcp-server.
 * @module config/server-config
 */

import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';

const ServerConfigSchema = z.object({
  rdapTimeoutMs: z.coerce.number().default(5000).describe('HTTP timeout for RDAP requests in ms.'),
  dohTimeoutMs: z.coerce.number().default(3000).describe('HTTP timeout for DoH requests in ms.'),
  rdapMaxRetries: z.coerce
    .number()
    .default(2)
    .describe('Max retry attempts on transient RDAP failures.'),
  dohMaxRetries: z.coerce
    .number()
    .default(2)
    .describe('Max retry attempts on transient DoH failures.'),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

let _config: ServerConfig | undefined;

/** Returns the parsed server config, lazy-initialized on first call. */
export function getServerConfig(): ServerConfig {
  _config ??= parseEnvConfig(ServerConfigSchema, {
    rdapTimeoutMs: 'RDAP_TIMEOUT_MS',
    dohTimeoutMs: 'DOH_TIMEOUT_MS',
    rdapMaxRetries: 'RDAP_MAX_RETRIES',
    dohMaxRetries: 'DOH_MAX_RETRIES',
  });
  return _config;
}
