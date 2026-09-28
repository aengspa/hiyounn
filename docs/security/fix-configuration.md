# Configuring settings that security fixes introduce

Some fixes from **전체 수정하기** make the code read a new environment variable
(a signing key, a host allowlist, a secret moved out of the code). These fixes
**fail closed**: until the variable is set, the affected feature rejects
requests instead of running insecurely. The product lists every such variable
on the fix result ("받은 파일을 반영하기 전에 설정할 환경변수") and in
`HOI-SECURITY-FIX-SUMMARY.md` inside the downloaded ZIP
(`src/lib/remediation/requiredEnv.ts`).

This page is the recommended setup for the two cases seen in the benchmark
(`scripts/e2e/fixtures/shop-api.txt`, fixed by `bedrock-gpt-5.6-luna`), plus the
general rules.

## Where to set variables

| Environment | Where | Notes |
|---|---|---|
| Local | `.env.local` (gitignored) | Restart `npm run dev` after changes. |
| Vercel | Project → Settings → Environment Variables | Set for **Production** and **Preview** separately, then redeploy. Changes do not apply to existing deployments. |
| Anything else | Your secret manager / runtime env | Never commit values; never prefix secrets with `NEXT_PUBLIC_`. |

## `JWT_SECRET`, the token signing key

**What the fix does** (`src/lib/auth.js`): replaces `jwt.decode(token)` (no
signature check, so anyone can forge a token) with

```js
if (!process.env.JWT_SECRET) return res.status(500).json({ error: "authentication unavailable" });
claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
```

**Recommended setup**

1. Find who **issues** the tokens. `JWT_SECRET` must be the same HMAC key the
   issuer signs with. A different value rejects every login.
2. If you control the issuer, generate a new key with at least 32 random bytes:
   ```bash
   openssl rand -base64 48
   ```
   Set the same value on the issuer and on this API. Existing tokens signed
   with the old key stop working, so users log in again once.
3. If the issuer signs with **RS256/ES256** (Auth0, Clerk, Cognito, Firebase,
   and Supabase projects using asymmetric keys), an HMAC secret is the wrong
   tool. Don't set `JWT_SECRET`. Change the fix to verify with the issuer's
   public key or JWKS and pin that algorithm (`algorithms: ["RS256"]`).
4. Keep tokens short-lived (for example `expiresIn: "15m"` plus a refresh
   token). `jwt.verify` enforces `exp` when present.

**Verify it:** a request with a valid token → 200; with a token signed by
another key or with `alg: none` → 401; with `JWT_SECRET` unset → 500
("authentication unavailable"). That last case is the intended fail-closed
state, so don't treat it as a bug to silence.

**Rotation:** changing the key logs everyone out. For zero-downtime rotation,
verify against both keys during a transition (try the new key, then the old
one) and remove the old key once its tokens have expired.

## `PREVIEW_ALLOWED_HOSTS`, the link-preview allowlist

**What the fix does** (`src/routes/preview.js`): the preview endpoint used to
`fetch()` any URL a user sent, which is SSRF: it could reach internal services or
cloud metadata such as `http://169.254.169.254/`. It now only fetches a URL when
all of these hold:

- the hostname is **exactly** in `PREVIEW_ALLOWED_HOSTS` (comma-separated,
  lowercase compare; no wildcards);
- the scheme is `http`/`https`, the port is 80/443, and there is no `user:pass@`;
- the hostname is not `localhost`, `*.localhost` or `*.local`;
- DNS resolves only to public addresses (private, loopback, link-local, CGNAT
  and multicast ranges are rejected);
- each redirect (up to 5) passes the same checks;
- the response arrives within 5 s and is at most 1 MB.

An **empty or unset** allowlist rejects every preview (400).

**Recommended setup**

```bash
# only hosts you actually want previews for; no scheme, port or path
PREVIEW_ALLOWED_HOSTS=example.com,www.example.com,docs.example.com
```

- List each host, including `www.`, because subdomains are not implied.
- Never list `localhost`, internal hostnames, raw IPs, or hosts that let anyone
  publish content on their own subdomains.
- If you want previews of *arbitrary* public sites, an allowlist can't cover
  that. Run the preview fetch through an egress proxy that blocks private
  ranges at the network level, and keep the code checks as a second layer.

**Remaining risk to know about:** the check resolves DNS, then `fetch` resolves
again, so a DNS-rebinding host could return a public address first and a private
one second. Allowlisting only hosts you trust closes this in practice. For
arbitrary hosts, use the egress proxy, or connect to the already-validated IP
with the original `Host` header.

**Verify it:** an allowed host → 200 with a title; `?url=http://169.254.169.254/`
→ 400; `?url=http://localhost:3000/` → 400; a host not on the list → 400.

## Other variables fixes introduce

- **Secrets moved out of code** (for example `STRIPE_SECRET`, `API_KEY`): the old
  value was in the code, so treat it as leaked. **Issue a new key**, set the new
  value, then revoke the old one at the provider. Moving it to an env var alone
  doesn't undo the exposure.
- **Anything else** a fix reads: the fix summary says which file needs it. Set
  it in every environment the code runs in before you deploy the fixed files.
