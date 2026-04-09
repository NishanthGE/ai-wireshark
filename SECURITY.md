# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | Yes       |
| < 3.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in AI Wireshark, please report it responsibly:

1. **Do not** open a public issue
2. Email the maintainer at **nishanthge01@gmail.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive a response within 48 hours
4. A fix will be released as soon as possible

## Security Best Practices

When using AI Wireshark:

- Store API keys in `.env` file (never in `config.py`)
- Run with minimal required privileges
- Keep the tool updated with `git pull`
- Do not expose the web dashboard (port 8080) to the public internet
- Review blocked IPs before deploying auto-block in production
