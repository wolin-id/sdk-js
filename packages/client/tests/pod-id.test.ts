import { describe, expect, it } from 'vitest';
import {
  DEFAULT_WOLIN_DOMAIN,
  DEFAULT_WOLIN_ISSUER,
  DEFAULT_WOLIN_OIDC_ISSUER,
  DEFAULT_WOLIN_POD_BASE_URL,
  isReservedPodId,
  isValidPodId,
  MAX_POD_ID_LEN,
  MIN_POD_ID_LEN,
  validatePodId,
} from '../src/index.js';

describe('@wolin-id/client — Production Endpoints & pod_id Validation', () => {
  it('exposes canonical Wolin (月印千江) production endpoints', () => {
    expect(DEFAULT_WOLIN_OIDC_ISSUER).toBe('https://auth.wolin.id');
    expect(DEFAULT_WOLIN_ISSUER).toBe('https://auth.wolin.id');
    expect(DEFAULT_WOLIN_POD_BASE_URL).toBe('https://pod.wolin.id');
    expect(DEFAULT_WOLIN_DOMAIN).toBe('wolin.id');
    expect(MIN_POD_ID_LEN).toBe(3);
    expect(MAX_POD_ID_LEN).toBe(32);
  });

  it('validates legal 3..32 lowercase [a-z0-9-] tenant pod_id handles', () => {
    for (const valid of [
      'alice',
      'bob',
      'luna-01',
      'a1b',
      'abc',
      'a'.repeat(32),
      'wolin-explorer-2026',
    ]) {
      expect(isValidPodId(valid)).toBe(true);
      expect(validatePodId(valid)).toEqual({ valid: true });
    }
  });

  it('rejects out-of-range lengths, uppercase, invalid chars, leading/trailing hyphens, --, and xn--', () => {
    const invalidSyntactic = [
      '',
      'a',
      'ab',
      'a'.repeat(33),
      '-alice',
      'alice-',
      'alice--bob',
      'xn--bcher-kva',
      'xn--wolin',
      'ab--cd',
      'Alice',
      'ALICE',
      'alice_bob',
      'alice.bob',
      'alice/bob',
      'alice bob',
      '월인',
    ];

    for (const bad of invalidSyntactic) {
      expect(isValidPodId(bad)).toBe(false);
      const res = validatePodId(bad);
      expect(res.valid).toBe(false);
      if (!res.valid) {
        expect(res.code).toBe('invalid_pod_id');
      }
    }
  });

  it('blocks reserved system/infrastructure pod_id handles by default', () => {
    for (const reserved of ['auth', 'pod', 'pods', 'admin', 'api', 'www', 'wolin', 'oidc']) {
      expect(isReservedPodId(reserved)).toBe(true);
      expect(isValidPodId(reserved)).toBe(false);
      const res = validatePodId(reserved);
      expect(res).toEqual({
        valid: false,
        code: 'reserved_pod_id',
        reason: `pod_id '${reserved}' is reserved for system infrastructure`,
      });
      expect(isValidPodId(reserved, { allowReserved: true })).toBe(true);
    }
    // 2-char reserved labels fail length check first and remain in RESERVED_POD_IDS
    expect(isReservedPodId('id')).toBe(true);
    expect(isValidPodId('id')).toBe(false);
  });
});
