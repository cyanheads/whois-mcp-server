#!/usr/bin/env node
/**
 * @fileoverview whois-mcp-server MCP server entry point.
 * @module index
 */

import { createApp } from '@cyanheads/mcp-ts-core';
import { appOptions } from './app.js';

await createApp(appOptions);
