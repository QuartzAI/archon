/**
 * Opt-in web authentication (Better Auth) barrel.
 *
 * See ./config for the opt-in gate + pure helpers and ./instance for the lazy
 * Better Auth singleton (`getAuth`).
 */
export {
  isWebAuthEnabled,
  assertWebAuthAtBoot,
  parseAllowedEmails,
  isEmailAllowed,
  getSignupMode,
  isApiGateEnabled,
  isHeaderAuthEnabled,
  isIapJwtEnabled,
  isArchonOwnedAuthPath,
  MIN_BETTER_AUTH_SECRET_LENGTH,
} from './config';
export { normalizeProxyIdentity } from './proxy-header';
export { verifyIapAssertion, IAP_ASSERTION_HEADER, type IapIdentity } from './iap-jwt';
export { getAuth, closeAuth, resetAuthForTest, type AuthInstance } from './instance';
