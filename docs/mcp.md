# MCP integration

The v0.1 server exposes:

- `security_initialize`
- `security_requirements`
- `security_threat_model`
- `security_scan`
- `security_gate`

The server uses the current MCP TypeScript server SDK and stdio transport. Configure your coding agent to launch `node dist/mcp/server.js` (after building) from the project root. Never grant the security server broader filesystem/network permissions than the agent itself needs.
