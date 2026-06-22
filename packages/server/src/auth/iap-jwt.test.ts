import { describe, test, expect, beforeAll } from 'bun:test';
import { SignJWT, generateKeyPair, type CryptoKey } from 'jose';
import { verifyIapAssertion } from './iap-jwt';

const ISSUER = 'https://cloud.google.com/iap';
const AUDIENCE = '/projects/123456789/global/backendServices/987654321';

let privateKey: CryptoKey;
let publicKey: CryptoKey;

/** Mint an ES256 JWT mimicking an IAP assertion, with per-test overrides. */
async function mintToken(
  overrides: {
    email?: string | null;
    sub?: string;
    issuer?: string;
    audience?: string;
    expiresIn?: string | number;
    issuedAt?: number;
    key?: CryptoKey;
  } = {}
): Promise<string> {
  const payload: Record<string, unknown> = { sub: overrides.sub ?? 'accounts.google.com:12345' };
  if (overrides.email !== null) payload.email = overrides.email ?? 'ze@myquartz.ai';

  let jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(overrides.issuer ?? ISSUER)
    .setAudience(overrides.audience ?? AUDIENCE)
    .setIssuedAt(overrides.issuedAt);
  jwt = jwt.setExpirationTime(overrides.expiresIn ?? '5m');
  return jwt.sign(overrides.key ?? privateKey);
}

describe('auth/iap-jwt', () => {
  beforeAll(async () => {
    // `extractable: true` so jose can serialize the key for ES256 ops in tests.
    const pair = await generateKeyPair('ES256', { extractable: true });
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
  });

  describe('verifyIapAssertion', () => {
    test('returns the email + sub for a valid, correctly-audienced token', async () => {
      const token = await mintToken();
      const identity = await verifyIapAssertion(token, AUDIENCE, publicKey);
      expect(identity.email).toBe('ze@myquartz.ai');
      expect(identity.sub).toBe('accounts.google.com:12345');
    });

    test('REJECTS a token minted for a different backend (audience mismatch)', async () => {
      const token = await mintToken({
        audience: '/projects/123456789/global/backendServices/000000000',
      });
      await expect(verifyIapAssertion(token, AUDIENCE, publicKey)).rejects.toThrow();
    });

    test('REJECTS a token with the wrong issuer', async () => {
      const token = await mintToken({ issuer: 'https://evil.example.com' });
      await expect(verifyIapAssertion(token, AUDIENCE, publicKey)).rejects.toThrow();
    });

    test('REJECTS an expired token', async () => {
      // Absolute epoch seconds in the past: issued 1970, expired 1970.
      const token = await mintToken({ issuedAt: 500, expiresIn: 1000 });
      await expect(verifyIapAssertion(token, AUDIENCE, publicKey)).rejects.toThrow();
    });

    test('REJECTS a token signed by a different (forged) key', async () => {
      const attacker = await generateKeyPair('ES256', { extractable: true });
      const token = await mintToken({ key: attacker.privateKey });
      // Verified against the legitimate public key → signature fails.
      await expect(verifyIapAssertion(token, AUDIENCE, publicKey)).rejects.toThrow();
    });

    test('REJECTS a token missing the email claim', async () => {
      const token = await mintToken({ email: null });
      await expect(verifyIapAssertion(token, AUDIENCE, publicKey)).rejects.toThrow(/email/i);
    });

    test('REJECTS a structurally invalid token', async () => {
      await expect(verifyIapAssertion('not-a-jwt', AUDIENCE, publicKey)).rejects.toThrow();
    });
  });
});
