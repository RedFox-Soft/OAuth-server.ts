/*
 * The area's own harness, re-exported rather than copied: what these cases exercise is the state a
 * fresh instance is provisioned into, which is the same instance every other MCP spec runs against.
 * A second copy would drift from it on the first change to `mcp.enabled` or the seeded clients.
 */

export * from './mcp.config.js';
