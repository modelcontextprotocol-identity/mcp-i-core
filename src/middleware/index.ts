/**
 * MCP-I Middleware
 *
 * Primary entry point: `withMCPI(server, { crypto })` — adds identity,
 * handshake, and auto-proofs to any McpServer instance in one call.
 *
 * For the low-level `Server` API or custom patterns, use `createMCPIMiddleware` directly.
 */

export {
  createMCPIMiddleware,
  type MCPIConfig,
  type MCPIDelegationConfig,
  type MCPIIdentityConfig,
  type MCPIMiddleware,
  type MCPIToolDefinition,
  type MCPIToolHandler,
  type MCPIServer,
} from './with-mcpi.js';

export {
  withMCPI,
  generateIdentity,
  type WithMCPIOptions,
} from './with-mcpi-server.js';
