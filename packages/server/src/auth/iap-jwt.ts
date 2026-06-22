/**
 * Cryptographic verification of Google Cloud IAP identity assertions.
 *
 * WHY: the plaintext `X-Goog-Authenticated-User-Email` header (see
 * `normalizeProxyIdentity`) is only trustworthy when the network boundary
 * guarantees no client can set it directly — anyone who reaches the backend
 * past the load balancer can forge it by knowing a teammate's email. IAP also
 * injects `X-Goog-IAP-JWT-Assertion`: a JWT signed by Google (ES256) that
 * carries the authenticated identity and is bound to THIS backend service via
 * the `aud` claim. Verifying its signature against Google's published public
 * keys, and checking issuer + audience, removes the "forge the header" risk
 * independently of the firewall.
 *
 * Public keys: https://www.gstatic.com/iap/verify/public_key-jwk (JWK Set,
 * ES256). `createRemoteJWKSet` fetches once and caches, handling key rotation
 * and `kid` selection. The audience MUST be the backend service id string from
 * the LB, e.g. `/projects/<PROJECT_NUMBER>/global/backendServices/<BACKEND_ID>`
 * (Terraform output `iap_audience`) — this is what prevents a valid token minted
 * for a DIFFERENT IAP-protected service in the same project from being replayed.
 *
 * Docs: https://cloud.google.com/iap/docs/signed-headers-howto
 */
import { createRemoteJWKSet, jwtVerify } from 'jose';

/** IAP's published ES256 JWK Set for signed-header verification. */
const IAP_JWKS_URL = new URL('https://www.gstatic.com/iap/verify/public_key-jwk');
/** Fixed issuer for IAP-signed assertions. */
const IAP_ISSUER = 'https://cloud.google.com/iap';
/** The IAP assertion header name (case-insensitive on lookup). */
export const IAP_ASSERTION_HEADER = 'X-Goog-IAP-JWT-Assertion';

/** Key resolver type accepted by `jwtVerify` (remote JWKS fn, or a key for tests). */
type VerifyKey = Parameters<typeof jwtVerify>[1];

// Lazily-created, process-cached remote JWKS. jose handles fetch, caching,
// cooldown, and rotation. Not created at import time so unit tests (which pass
// their own key) and JWT-disabled deploys never trigger a network fetch.
let remoteJwks: VerifyKey | undefined;
function getRemoteJwks(): VerifyKey {
  remoteJwks ??= createRemoteJWKSet(IAP_JWKS_URL);
  return remoteJwks;
}

/** The verified identity carried by an IAP assertion. */
export interface IapIdentity {
  /** The authenticated user's email (the `email` claim). */
  email: string;
  /** Google's stable subject id (the `sub` claim), for reference/logging. */
  sub: string;
}

/**
 * Verify an IAP assertion JWT and return the authenticated identity.
 *
 * Throws if the signature is invalid, the issuer/audience don't match, the
 * token is expired/not-yet-valid, or the `email` claim is absent. Callers
 * should treat any throw as "no trusted identity" (fail closed).
 *
 * @param token    raw `X-Goog-IAP-JWT-Assertion` header value
 * @param audience the backend service id string (`ARCHON_IAP_JWT_AUDIENCE`)
 * @param key      key resolver; defaults to Google's remote JWKS. Tests inject
 *                 a local public key to verify locally-signed tokens.
 */
export async function verifyIapAssertion(
  token: string,
  audience: string,
  key: VerifyKey = getRemoteJwks()
): Promise<IapIdentity> {
  const { payload } = await jwtVerify(token, key, {
    issuer: IAP_ISSUER,
    audience,
    algorithms: ['ES256'],
  });
  const email = typeof payload.email === 'string' ? payload.email : undefined;
  if (!email) {
    throw new Error('IAP assertion is missing the required "email" claim');
  }
  const sub = typeof payload.sub === 'string' && payload.sub ? payload.sub : email;
  return { email, sub };
}
