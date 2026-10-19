"""Security Scanner MCP Server
Autonomous HTTP Security Headers & RFC 9116 Audit Tool for AI Agents and Developers.
Compliant with Model Context Protocol (MCP) and Smithery / Glama specifications.
"""

import sys
import json
import urllib.request
import urllib.error
import ssl
from typing import Dict, Any, List

def analyze_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    norm = {k.lower(): v for k, v in headers.items()}
    checks = [
        ("content-security-policy", "Content-Security-Policy (CSP)", "Empêche l'exécution de scripts non autorisés (XSS)", 25),
        ("strict-transport-security", "Strict-Transport-Security (HSTS)", "Force l'utilisation du protocole HTTPS sécurisé", 20),
        ("x-content-type-options", "X-Content-Type-Options", "Empêche le sniffing MIME par le navigateur", 15),
        ("x-frame-options", "X-Frame-Options", "Protège contre le détournement de clics (Clickjacking)", 15),
        ("referrer-policy", "Referrer-Policy", "Contrôle les données d'URL transmises aux tiers", 10),
        ("permissions-policy", "Permissions-Policy", "Restreint l'accès aux APIs sensibles (caméra, micro, géo)", 10),
        ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy (COOP)", "Isole le contexte de navigation contre les attaques cross-origin", 5)
    ]
    
    score = 0
    details = []
    for header_name, title, desc, points in checks:
        present = header_name in norm
        if present:
            score += points
        details.append({
            "header": header_name,
            "title": title,
            "present": present,
            "points": points if present else 0,
            "max_points": points,
            "value": norm.get(header_name, None),
            "description": desc
        })
        
    grade = "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 35 else "F"
    return {
        "score": score,
        "max_score": 100,
        "grade": grade,
        "checks": details
    }

def scan_target_url(target_url: str) -> Dict[str, Any]:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
        
    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "KaiSecurityScanner/1.0 (+https://github.com/Mateidslx/kai-agent)"}
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            raw_headers = dict(resp.headers)
            analysis = analyze_headers(raw_headers)
            return {
                "ok": True,
                "target_url": target_url,
                "status_code": resp.status,
                "analysis": analysis,
                "raw_headers_count": len(raw_headers)
            }
    except urllib.error.HTTPError as e:
        raw_headers = dict(e.headers)
        analysis = analyze_headers(raw_headers)
        return {
            "ok": True,
            "target_url": target_url,
            "status_code": e.code,
            "analysis": analysis,
            "raw_headers_count": len(raw_headers)
        }
    except Exception as e:
        return {
            "ok": False,
            "target_url": target_url,
            "error": str(e)
        }

def check_security_txt(domain: str) -> Dict[str, Any]:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    paths = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt"
    ]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for url in paths:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "KaiSecurityScanner/1.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
                if resp.status == 200:
                    content = resp.read().decode("utf-8", errors="ignore")
                    lines = [l.strip() for l in content.split("\n") if l.strip() and not l.startswith("#")]
                    contacts = [l.replace("Contact:", "").strip() for l in lines if l.lower().startswith("contact:")]
                    expires = [l.replace("Expires:", "").strip() for l in lines if l.lower().startswith("expires:")]
                    return {
                        "found": True,
                        "url": url,
                        "contacts": contacts,
                        "expires": expires[0] if expires else None,
                        "raw_snippet": content[:300]
                    }
        except:
            continue
            
    return {"found": False, "domain": domain}

# JSON-RPC Standard Stdio Loop for MCP
def run_stdio_server():
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})
            
            if method == "initialize":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": "security-scanner-mcp",
                            "version": "1.0.0"
                        },
                        "capabilities": {
                            "tools": {}
                        }
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
            elif method == "tools/list":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "scan_url_security_headers",
                                "description": "Scan an HTTP/HTTPS URL for 7 critical OWASP security headers (CSP, HSTS, X-Frame-Options, etc.) and calculate a security grade from A+ to F.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "url": {"type": "string", "description": "The target URL or domain to audit (e.g. 'https://api.ovh.com')"}
                                    },
                                    "required": ["url"]
                                }
                            },
                            {
                                "name": "check_rfc9116_security_txt",
                                "description": "Verify whether a domain publishes an RFC 9116 security.txt file with responsible vulnerability disclosure contacts.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "domain": {"type": "string", "description": "The target domain name (e.g. 'doctolib.fr')"}
                                    },
                                    "required": ["domain"]
                                }
                            }
                        ]
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
            elif method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments", {})
                if tool_name == "scan_url_security_headers":
                    data = scan_target_url(args.get("url", ""))
                elif tool_name == "check_rfc9116_security_txt":
                    data = check_security_txt(args.get("domain", ""))
                else:
                    data = {"error": f"Unknown tool: {tool_name}"}
                    
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(data, indent=2)
                            }
                        ]
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
            else:
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {}
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": str(e)}
            }
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    run_stdio_server()
