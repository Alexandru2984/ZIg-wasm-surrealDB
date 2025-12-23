# Security Documentation

## Threat Model

### Assets Protected
- User credentials (email, password hashes)
- Session tokens
- Verification codes (email confirmation, password reset)
- User tasks and personal data

### Attack Vectors Mitigated

| Threat | Mitigation | Status |
|--------|------------|--------|
| **Path Traversal** | Block `..`, validate realpath stays in `/public` | ✅ |
| **Hidden File Access** | Block `.env`, `.git`, config files | ✅ |
| **JSON Injection** | Use `std.json` parsing via `json.zig` | ✅ |
| **XSS** | Security headers (nosniff, X-Frame-Options) | ✅ |
| **CORS Abuse** | Configurable origin via `.env` | ✅ |
| **Memory Leaks** | `defer allocator.free()` on all owned buffers | ✅ |
| **Secret Logging** | Removed verification code from logs | ✅ |

---

## Security Headers

All API responses include:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 1; mode=block
```

HTML static files also include CSP:
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; ...
```

---

## Configuration

Security-sensitive settings in `.env`:
```env
CORS_ORIGIN=https://your-domain.com  # Never use * in production
```

---

## Production Recommendations

1. **Rate Limiting**: Configure in Nginx for `/api/auth/*`
2. **HTTPS**: Always use HTTPS in production
3. **Database**: Use strong SurrealDB credentials
4. **Secrets**: Never commit `.env` to version control
5. **Logs**: Monitor for security events, don't log secrets

---

## Reporting Security Issues

If you discover a security vulnerability, please report it privately.
