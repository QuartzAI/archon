# Archon App Adaptations for IAP-Only GCP Deployment

> **Status:** Tier 1 + Tier 2 IMPLEMENTED (2026-06-22) — see §10. §6 deploy bits pending.
> **Recommended posture:** IAP JWT verification (`ARCHON_IAP_JWT_AUDIENCE`), NOT the plaintext header.
> **Companion doc:** `~/repos/terraform/docs/plans/archon-deployment.md` (the GCP infra plan)
> **Context:** Deploy a single shared Archon instance on a CE VM behind a Google Cloud
> external HTTPS LB + **IAP** (Google SSO, `domain:myquartz.ai`). Webhooks bypass IAP.
> **Auth decision:** IAP only — **no Better Auth, no Caddy.**
> **Last updated:** 2026-06-20

---

## 1. TL;DR — what the code does today vs. what we need

| Capability                                      | Today                                                                                               | Needed for IAP-only                    | Gap?                                               |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------- | -------------------------------------------------- |
| Read identity from a trusted proxy header       | ✅ `ARCHON_WEB_AUTH_HEADER` (default `X-Archon-User`) read in `resolveAuthContext`/`requireWebUser` | Read `X-Goog-Authenticated-User-Email` | env var only                                       |
| Strip IAP's `accounts.google.com:` email prefix | ❌ value stored **raw**                                                                             | normalize to bare email                | **CODE**                                           |
| `/api/*` gate enforced without Better Auth      | ❌ gate requires `DATABASE_URL && BETTER_AUTH_SECRET`                                               | enforce in header-only mode            | **CODE** (or accept IAP+firewall as the only gate) |
| Per-user GitHub identity off header userId      | ✅ flows through resolved `web.userId`                                                              | same                                   | none                                               |
| Per-user AI keys off header userId              | ✅ flows through resolved `web.userId`                                                              | same                                   | none                                               |
| Webhooks bypass IAP & self-auth                 | ✅ `/webhooks/*` outside `/api/*`, HMAC/Bearer                                                      | same                                   | none                                               |
| Run app without Caddy/TLS (LB terminates)       | ✅ plain HTTP `:3000`                                                                               | same                                   | compose/env only                                   |

**Bottom line:** Identity attribution from the IAP header **already works without Better Auth**
(`resolveAuthContext` step 2 reads the header regardless of Better Auth state). Two real code
gaps remain: (1) the IAP email **prefix is not stripped**, and (2) the **server-side `/api/*`
gate cannot be turned on** without Better Auth. Both are small, localized changes.

---

## 2. Ground truth (verified code references)

### 2.1 The `/api/*` gate — requires Better Auth

`packages/server/src/auth/config.ts:94`

```ts
export function isApiGateEnabled(env = process.env): boolean {
  return isWebAuthEnabled(env) && env.ARCHON_WEB_AUTH_REQUIRED !== 'false';
}
// isWebAuthEnabled (line 25):
//   return Boolean(env.DATABASE_URL && env.BETTER_AUTH_SECRET);
```

`packages/server/src/routes/api.ts:1364`

```ts
app.use('/api/*', async (c, next) => {
  if (!isApiGateEnabled()) return next();   // ← OFF without Better Auth
  ...
  const ctx = await resolveAuthContext(c);
  if (!ctx) return apiError(c, 401, 'Authentication required');
});
```

→ With IAP-only (no `BETTER_AUTH_SECRET`), `isApiGateEnabled()` is **false**, so the gate
no-ops and never checks the header. Access control then rests **entirely on IAP + the VM
firewall**.

### 2.2 Header identity resolution — works without Better Auth, but no prefix strip

`packages/server/src/routes/api.ts:1416` (inside `resolveAuthContext`)

```ts
const headerName = process.env.ARCHON_WEB_AUTH_HEADER || 'X-Archon-User';
const headerVal = c.req.header(headerName)?.trim();
if (!headerVal) return undefined;
const user = await userDb.findOrCreateUserByPlatformIdentity('web', headerVal, headerVal);
return { userId: user.id, role: user.role };
```

Same pattern duplicated in `requireWebUser` at `api.ts:1477`.
→ IAP sends `accounts.google.com:ze@myquartz.ai`. That **whole string** becomes the
`user_identities.platform_user_id` (platform `'web'`) and the display name. Functional (stable),
but polluted and fragile if auth methods are ever mixed.

### 2.3 Per-user gates — keyed off the resolved `userId`, not Better Auth

`packages/core/src/github-auth/config.ts:25`

```ts
export function isPerUserGitHubEnabled(env = process.env): boolean {
  return Boolean(env.GITHUB_APP_ID && env.TOKEN_ENCRYPTION_KEY);
}
// GITHUB_APP_CLIENT_ID (Iv23…) additionally required for the device flow (loadDeviceFlowConfig).
```

Per-user AI provider keys gate on `TOKEN_ENCRYPTION_KEY` (`isPerUserProviderKeysEnabled`).
Both consume the `web.userId` from `requireWebUser` → **header-derived identity flows straight
through**. No Better Auth dependency. ✅

### 2.4 Webhooks — outside the gate

`packages/server/src/index.ts` ~758–860: `POST /webhooks/github` (HMAC `X-Hub-Signature-256`)
and `POST /webhooks/jira` (`Authorization: Bearer <JIRA_WEBHOOK_SECRET>`) are registered outside
`/api/*` and self-authenticate. `/api/health` is in `PUBLIC_API_GATE_PREFIXES` (`api.ts:1363`).
→ No change needed; the infra URL map routes `/webhooks/*` + `/api/health` to the non-IAP backend.

### 2.5 Existing security guard (keep it honest)

`packages/server/src/routes/api.ts:1357` and `index.ts:~980` already warn that the trusted
header is **only safe when the app is reachable solely through a proxy that strips it** (or binds
loopback). Our firewall (only LB ranges → :3000, no public ingress) is what makes this safe. The
plan must preserve that guarantee.

---

## 3. Design decision: how strongly to bind to IAP

Three tiers, all now implemented. **Recommended for IAP deploys: Tier 2** (cryptographic, not
forgeable). Tier 1 (plaintext header) remains for the Caddy sidecar / non-IAP proxy case.

### Tier 0 — Zero code (config only)

- Set `ARCHON_WEB_AUTH_HEADER=X-Goog-Authenticated-User-Email`. Identity attribution works.
- Accept: `platform_user_id` carries the `accounts.google.com:` prefix; the `/api/*` gate is
  **off** (IAP + firewall are the only access control).
- **Viable** because IAP rejects unauthenticated users at the edge and the firewall blocks
  direct VM access. But: no in-app defense-in-depth, polluted identities, and the
  `accounts.google.com:` string is brittle.
- Use only for a quick first bring-up.

### Tier 1 — Recommended (small, localized code)

Two changes:

1. **Normalize the IAP header** (strip `accounts.google.com:` → bare email) at the single
   resolution chokepoint.
2. **Allow the `/api/*` gate in header-only mode** so `ARCHON_WEB_AUTH_REQUIRED=true` enforces
   identity even without Better Auth — true defense-in-depth behind IAP.

### Tier 2 — Hardening (verify the signed IAP JWT)

- Instead of trusting a plaintext email header, verify `X-Goog-IAP-JWT-Assertion`
  (Google-signed; `aud` = the backend service ID from the infra plan output `iap_audience`).
- Removes the "what if someone reaches the VM and forges the header" risk **independently** of
  the firewall. The strongest option; more code (fetch Google JWKS, verify, extract `email`).
- Recommended once Tier 1 is stable. Not required if the firewall guarantee is trusted.

---

## 4. Tier 1 implementation

### 4.1 Add an IAP-aware identity normalizer

**New file:** `packages/server/src/auth/proxy-header.ts`

```ts
/**
 * Normalize the identity carried by the trusted reverse-proxy auth header.
 *
 * Google Cloud IAP sets `X-Goog-Authenticated-User-Email` to
 * `accounts.google.com:user@domain.com` (a namespaced subject, NOT a bare email).
 * Other proxies (the auth-service sidecar) send a bare value. We canonicalize to
 * the bare email so the `user_identities('web', …)` key is stable and human-readable.
 */
export function normalizeProxyIdentity(raw: string): string {
  const v = raw.trim();
  // IAP namespaced form: "<namespace>:<subject>" e.g. accounts.google.com:ze@myquartz.ai
  const idx = v.indexOf(':');
  if (idx > 0 && v.slice(0, idx).includes('.')) return v.slice(idx + 1).trim();
  return v;
}
```

_(Guard `idx > 0` + `namespace contains '.'` so we never split a plain value that happens to
contain a colon. Unit-test both the IAP form and a bare email.)_

### 4.2 Apply it at both resolution sites

`packages/server/src/routes/api.ts` — in **`resolveAuthContext`** (~1417) and **`requireWebUser`**
(~1478), replace the raw `headerVal` passed to `findOrCreateUserByPlatformIdentity` with the
normalized value:

```ts
const headerName = process.env.ARCHON_WEB_AUTH_HEADER || 'X-Archon-User';
const raw = c.req.header(headerName)?.trim();
if (!raw) return undefined; // (or the 401 branch in requireWebUser)
const headerVal = normalizeProxyIdentity(raw);
const user = await userDb.findOrCreateUserByPlatformIdentity('web', headerVal, headerVal);
```

Keep the existing error handling/logging untouched.

### 4.3 Enable the API gate in header-only mode

`packages/server/src/auth/config.ts` — add a header-auth predicate and widen the gate:

```ts
/** Header trust is active when a trusted reverse-proxy auth header is configured. */
export function isHeaderAuthEnabled(env = process.env): boolean {
  return Boolean(env.ARCHON_WEB_AUTH_HEADER);
}

export function isApiGateEnabled(env = process.env): boolean {
  return (
    (isWebAuthEnabled(env) || isHeaderAuthEnabled(env)) && env.ARCHON_WEB_AUTH_REQUIRED !== 'false'
  );
}
```

**Behavior matrix after this change:**
| `ARCHON_WEB_AUTH_HEADER` | Better Auth | `ARCHON_WEB_AUTH_REQUIRED` | Gate |
|---|---|---|---|
| unset | off | — | OFF (solo/local unchanged) ✅ |
| set (IAP) | off | unset/true | **ON** (new — enforces identity) |
| set (IAP) | off | `false` | OFF (proxy-only posture) |
| set | on | true | ON (today's behavior) |

⚠️ **Regression check:** solo/local installs that set neither var stay OFF — confirm the default
path is byte-for-byte unchanged. Add a test asserting `isApiGateEnabled({}) === false`.

### 4.4 Boot warning stays

The existing non-loopback header-trust warning (`index.ts:~980`) already fires; no change. The
firewall is the runtime guarantee that the header can't be forged.

### 4.5 Tests

- `proxy-header.test.ts`: `accounts.google.com:a@b.com` → `a@b.com`; `a@b.com` → `a@b.com`;
  value with embedded colon but no dotted namespace → unchanged.
- `config.test.ts`: extend `isApiGateEnabled` truth table (the matrix above).
- Route test: with `ARCHON_WEB_AUTH_HEADER` set + Better Auth off, a request **without** the
  header → 401; **with** the header → resolves a user.

---

## 5. Tier 2 — verify the IAP JWT (IMPLEMENTED; this is the recommended posture)

**Why it matters:** the plaintext `X-Goog-Authenticated-User-Email` is only as strong as the
network boundary — anyone who reaches the backend directly (LB bypass, SSRF, a firewall
misconfig) can forge it by knowing a teammate's email. Tier 2 removes that dependency.

**What was built:**

- `packages/server/src/auth/iap-jwt.ts` — `verifyIapAssertion(token, audience, key?)` verifies the
  Google-signed `X-Goog-IAP-JWT-Assertion` using `jose`:
  - signature against IAP's JWKS (`https://www.gstatic.com/iap/verify/public_key-jwk`, ES256,
    fetched + cached + rotated by `createRemoteJWKSet`);
  - `iss` == `https://cloud.google.com/iap`;
  - `aud` == `ARCHON_IAP_JWT_AUDIENCE` (the backend service id string, infra output
    `iap_audience`) — **this binds the token to OUR backend**, rejecting tokens minted for any
    other IAP-protected service in the project (replay defense);
  - `exp`/`iat` validity; requires a non-empty `email` claim.
- New config gate `isIapJwtEnabled()` (`ARCHON_IAP_JWT_AUDIENCE` set); folded into
  `isApiGateEnabled` (gate ON when web auth OR JWT OR plaintext header is configured).
- `resolveProxyIdentity(c)` in `api.ts`: **JWT mode is exclusive** — when `ARCHON_IAP_JWT_AUDIENCE`
  is set, the plaintext header is NOT consulted at all, so a forged `X-Goog-Authenticated-User-Email`
  does nothing. Missing/invalid assertion → undefined (fail closed → 401).
- `jose@^6.1.0` added as a direct dep of `@archon/server` (matches better-auth's peer range).
- 7 deterministic crypto tests (locally-signed ES256 tokens): valid token, audience mismatch,
  wrong issuer, expired, **forged key**, missing email, malformed — all reject as expected.

**Operator config:** set `ARCHON_IAP_JWT_AUDIENCE=/projects/<PROJECT_NUMBER>/global/backendServices/<BACKEND_ID>`
(from the infra plan's `iap_audience` output). Leave `ARCHON_WEB_AUTH_HEADER` unset on IAP deploys.

**Residual note:** a JWKS-fetch outage fails closed (temporary 401s) — acceptable since IAP has
already authenticated the user at the edge; `jose` caches keys so this is rare.

---

## 6. Non-auth adaptations

### 6.1 Runtime config (VM `.env`) — no Caddy, no Better Auth

```ini
PORT=3000
DOMAIN=archon.myquartz.ai

# IAP-only identity (Tier 1)
ARCHON_WEB_AUTH_HEADER=X-Goog-Authenticated-User-Email
ARCHON_WEB_AUTH_REQUIRED=true        # now meaningful in header-only mode (§4.3)

# Postgres (Cloud SQL private IP) — required for multi-user features
DATABASE_URL=postgresql://archon:<pwd>@<private-ip>:5432/archon

# Multi-user GitHub (App mode) + per-user encrypted creds
GITHUB_APP_ID=<numeric>
GITHUB_APP_PRIVATE_KEY_PATH=/secrets/app.pem
GITHUB_APP_CLIENT_ID=Iv23...
WEBHOOK_SECRET=<random>
TOKEN_ENCRYPTION_KEY=<64 hex>

# Jira (webhook; bypasses IAP)
JIRA_BASE_URL=https://myquartz.atlassian.net
JIRA_USER=bot@myquartz.ai
JIRA_API_TOKEN=<token>
JIRA_WEBHOOK_SECRET=<secret>
JIRA_ALLOWED_USERS=...

ARCHON_DATA=/opt/archon-data         # PD-SSD bind mount
```

> **Note on Postgres without Better Auth:** `DATABASE_URL` is set (needed for users, per-user
> tokens, workflow scale), but `BETTER_AUTH_SECRET` is intentionally **unset** → Better Auth
> stays off, the Better Auth tables stay unpopulated, and IAP is the only login. This is a
> supported combination (the `remote_agent_auth_*` tables are created-but-empty on Postgres).

### 6.2 Compose invocation

- Run the **`app` service only**: `docker compose pull && docker compose up -d`.
- **Drop `--profile cloud`** (LB terminates TLS) and **`--profile with-db`** (use Cloud SQL).
- Confirm the base `app` service binds `:3000` and does not require Caddy. No image change.

### 6.3 Jira adapter — finish the in-flight change

Working tree has uncommitted edits to `packages/adapters/src/forge/jira/adapter.ts`:

- Webhook auth via `Authorization: Bearer <secret>` (replacing `?secret=` query param).
- Fallback: treat a payload with a comment but no `webhookEvent` as `comment_created`.
  **Action:** finish, test, and land these on `dev` before deploying — the production Jira
  Automation webhook will send the Bearer header, so this must be the deployed behavior. (Also
  reconcile `JIRA_BOT_MENTION` default and `JIRA_ALLOWED_USERS` parsing with the infra `.env`.)

### 6.4 `.env.example` + docs

- Add an **"IAP / reverse-proxy identity (no Better Auth)"** stanza documenting
  `ARCHON_WEB_AUTH_HEADER=X-Goog-Authenticated-User-Email` + `ARCHON_WEB_AUTH_REQUIRED=true`,
  with the security note that the proxy/firewall MUST prevent direct access (header forgery).
- Update `packages/docs-web/.../deployment/` with an IAP section (the Docker guide currently
  only covers Caddy basic/form auth + Better Auth).

---

## 7. Change inventory & blast radius

| #   | Change                                  | Files                                                                    | Risk                                              |
| --- | --------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------- |
| 1   | `normalizeProxyIdentity` helper + tests | `auth/proxy-header.ts` (new), `*.test.ts`                                | low (pure fn)                                     |
| 2   | Apply normalizer at 2 sites             | `routes/api.ts` (~1417, ~1478)                                           | low                                               |
| 3   | Header-only API gate                    | `auth/config.ts` (`isApiGateEnabled`, new `isHeaderAuthEnabled`) + tests | **med** — touches global gate; guard solo default |
| 4   | Land Jira adapter edits                 | `forge/jira/adapter.ts`                                                  | low–med                                           |
| 5   | `.env.example` + deployment docs        | `.env.example`, `packages/docs-web/...`                                  | none                                              |
| 6   | (Tier 2) IAP JWT verify middleware      | `auth/iap-jwt.ts` (new) + wiring                                         | med (new dep)                                     |

All changes are reversible and behind env flags — unset the vars → today's behavior. Branch off
`dev`, PR via the template, `bun run validate` before merge (per CLAUDE.md).

---

## 8. Open items to confirm during implementation

1. **Exact IAP header value** on this LB (`accounts.google.com:<email>` vs `<email>`) — verify
   against a live request before trusting the strip logic; adjust `normalizeProxyIdentity` if the
   namespace differs.
2. **Do we even enable the gate?** If we fully trust IAP + firewall, Tier 1 §4.3 is
   defense-in-depth, not strictly required. Recommended on, but it's a judgment call — leaving it
   off (`ARCHON_WEB_AUTH_REQUIRED=false`, or simply not enabling header mode) is the
   IAP-edge-only posture.
3. **Display name backfill** — IAP only gives email; `name` falls back to email. Fine; note it.
4. **Tier 2 timing** — ship Tier 1 first, validate end-to-end, then decide on JWT verification.

---

## 10. Implementation status (2026-06-22)

**Tier 1 — DONE** (code only; not yet committed/PR'd):

- ✅ `packages/server/src/auth/proxy-header.ts` — `normalizeProxyIdentity()` (strips IAP's
  `accounts.google.com:` namespace; leaves bare emails / opaque usernames intact).
- ✅ `packages/server/src/auth/proxy-header.test.ts` — 8 tests, all passing.
- ✅ `packages/server/src/auth/config.ts` — new `isHeaderAuthEnabled()`; `isApiGateEnabled()`
  now `(isWebAuthEnabled || isHeaderAuthEnabled) && ARCHON_WEB_AUTH_REQUIRED !== 'false'`.
- ✅ `packages/server/src/auth/index.ts` — barrel exports `isHeaderAuthEnabled` + `normalizeProxyIdentity`.
- ✅ `packages/server/src/routes/api.ts` — `normalizeProxyIdentity` applied in BOTH
  `resolveAuthContext` (~1417) and `requireWebUser` (~1478).
- ✅ `packages/server/src/auth/config.test.ts` — extended `isApiGateEnabled` matrix +
  `isHeaderAuthEnabled` tests (25 pass). Solo default `isApiGateEnabled({}) === false` asserted.
- ✅ `packages/server/package.json` — `proxy-header.test.ts` added to the test split.
- ✅ `.env.example` — IAP / reverse-proxy header stanza + `ARCHON_WEB_AUTH_REQUIRED` note updated.
- ✅ Validated: server `type-check` clean, eslint clean (prod files), prettier clean,
  `proxy-header`/`config`/`api.auth`/`resolve-user-id` tests pass.

**Tier 2 — DONE** (code only; not yet committed/PR'd) — see §5:

- ✅ `packages/server/src/auth/iap-jwt.ts` — `verifyIapAssertion` (ES256, JWKS, iss/aud/exp).
- ✅ `packages/server/src/auth/iap-jwt.test.ts` — 7 crypto tests (incl. forged-key & audience).
- ✅ `auth/config.ts` — `isIapJwtEnabled()`; folded into `isApiGateEnabled` + tests.
- ✅ `routes/api.ts` — `resolveProxyIdentity` (JWT-exclusive; plaintext ignored in JWT mode).
- ✅ `auth/index.ts` barrel exports; `package.json` test split + `jose@^6.1.0` dep.
- ✅ `.env.example` — `ARCHON_IAP_JWT_AUDIENCE` documented as the recommended posture.
- ✅ Validated: server type-check, eslint, prettier clean; iap-jwt(7)+config(29)+api.auth(18) pass.

**Still pending:**

- ⏳ Commit on a branch off `dev` + PR (currently uncommitted on `feat/jira-plan-both-types`).
- ⏳ Full `bun run validate` before PR (per CLAUDE.md).
- ⏳ §6.3 Jira adapter edits — finish/land the in-flight Bearer-auth change.
- ⏳ §6.4 deployment docs (`packages/docs-web/.../deployment/` IAP section).
- ⏳ §8.1 — verify the live IAP JWT (`aud` value) end-to-end after infra is up.

## 9. Sequence (relative to infra plan)

1. Land code (Tier 1 §4) + Jira adapter (§6.3) on `dev`; `bun run validate`; merge.
2. Build/publish image (existing `publish.yml` → ghcr) — or pin a tag.
3. Infra plan steps 1–7 (VM, Cloud SQL, LB, IAP). Deploy app with §6.1 `.env`.
4. **Verify §8.1** against a real IAP request; confirm a user row is created with the bare email.
5. GitHub App + Jira Automation webhooks; test `@archon` round-trip (webhook path, no IAP).
6. Confirm a teammate can log into the Web UI via Google SSO, connect their GitHub + AI creds,
   and that a Web-UI-started run is attributed to their email.
7. (Later) Tier 2 JWT hardening.
