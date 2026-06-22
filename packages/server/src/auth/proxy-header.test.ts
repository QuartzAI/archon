import { describe, test, expect } from 'bun:test';
import { normalizeProxyIdentity } from './proxy-header';

describe('auth/proxy-header', () => {
  describe('normalizeProxyIdentity', () => {
    test('strips the IAP namespace prefix (accounts.google.com:)', () => {
      expect(normalizeProxyIdentity('accounts.google.com:ze@myquartz.ai')).toBe('ze@myquartz.ai');
    });

    test('strips other dotted-host namespaces too', () => {
      expect(normalizeProxyIdentity('securetoken.google.com:user@x.com')).toBe('user@x.com');
    });

    test('leaves a bare email unchanged', () => {
      expect(normalizeProxyIdentity('ze@myquartz.ai')).toBe('ze@myquartz.ai');
    });

    test('leaves an opaque username unchanged (no colon)', () => {
      expect(normalizeProxyIdentity('alice')).toBe('alice');
    });

    test('does NOT split when the pre-colon segment is not a dotted host', () => {
      // e.g. an opaque "scheme:value" username — keep it intact.
      expect(normalizeProxyIdentity('user:name')).toBe('user:name');
    });

    test('does NOT split when nothing follows the colon', () => {
      expect(normalizeProxyIdentity('accounts.google.com:')).toBe('accounts.google.com:');
    });

    test('does NOT split a leading-colon value', () => {
      expect(normalizeProxyIdentity(':weird')).toBe(':weird');
    });

    test('trims surrounding whitespace', () => {
      expect(normalizeProxyIdentity('  accounts.google.com:ze@myquartz.ai  ')).toBe(
        'ze@myquartz.ai'
      );
    });
  });
});
