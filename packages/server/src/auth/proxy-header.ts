/**
 * Normalize the identity carried by the trusted reverse-proxy auth header
 * (`ARCHON_WEB_AUTH_HEADER`).
 *
 * Google Cloud IAP sets `X-Goog-Authenticated-User-Email` to a NAMESPACED
 * subject, not a bare email: `accounts.google.com:user@domain.com`. Other
 * proxies (the auth-service sidecar, Caddy basicauth) send a bare value. We
 * canonicalize to the bare subject so the `user_identities('web', …)` key is
 * stable and human-readable regardless of which proxy fronts the deploy.
 *
 * The split only fires when the value looks like `<namespace>:<subject>` where
 * the namespace is a dotted host (e.g. `accounts.google.com`). A bare email has
 * no colon (returned unchanged), and a value whose pre-colon segment is not a
 * dotted host is left intact so we never mangle an opaque username that happens
 * to contain a colon.
 */
export function normalizeProxyIdentity(raw: string): string {
  const v = raw.trim();
  const idx = v.indexOf(':');
  if (idx <= 0) return v;
  const namespace = v.slice(0, idx);
  const subject = v.slice(idx + 1).trim();
  // Only strip a dotted-host namespace (IAP form) and only when a subject remains.
  if (subject && namespace.includes('.')) return subject;
  return v;
}
