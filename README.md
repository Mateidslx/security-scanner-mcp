# Security Scanner MCP Server

[![Smithery](https://smithery.ai/badge/@Mateidslx/security-scanner-mcp)](https://smithery.ai/server/@Mateidslx/security-scanner-mcp)
[![Glama](https://glama.ai/badge/mcp/security-scanner-mcp)](https://glama.ai/mcp/servers/security-scanner-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

Autonomous HTTP Security Headers & RFC 9116 Vulnerability Disclosure Auditor for AI Agents, Claude Desktop, Cursor, and Developers.

---

## 🛠️ Tools Included

### 1. `scan_url_security_headers`
Audits any target URL or domain for 7 critical OWASP security headers:
- `Content-Security-Policy (CSP)`
- `Strict-Transport-Security (HSTS)`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy (COOP)`

Computes an overall security grade from **A+ to F** and returns actionable remediation snippets (Nginx, Apache, Caddy, Cloudflare).

### 2. `check_rfc9116_security_txt`
Probes `/.well-known/security.txt` and `/security.txt` across target domains to discover responsible vulnerability disclosure contact points, bug bounty scopes, and PGP encryption keys.

---

## 🚀 1-Click Install via Smithery

Install automatically for Claude Desktop using the Smithery CLI:

```bash
npx -y @smithery/cli install @Mateidslx/security-scanner-mcp --client claude
```

Or for Cursor / Claude Code:
```bash
npx -y @smithery/cli install @Mateidslx/security-scanner-mcp --client cursor
```

---

## 💻 Manual Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "python",
      "args": ["security_scanner_mcp.py"]
    }
  }
}
```

---

## 🌐 Remote Streamable MCP & x402 Micropayments

This MCP server also runs as a remote Streamable HTTP / SSE endpoint:
- **Base Endpoint**: `https://gofrantic.com` / `http://88.96.47.180:8765/mcp`
- **x402 Protocol**: Enabled for machine-to-machine micropayments (`0.05 USDC` on Base network to `0x73320DbB0cE5714EC0F26c846059c956F4e2afee`).

---

## 📄 License

MIT © [Matéi de Saint Léger](https://github.com/Mateidslx)
