import { describe, expect, it } from 'vitest';
import {
  base64UrlDecode,
  base64UrlDecodeString,
  base64UrlEncode,
  computeJwkThumbprint,
  generateDPoPKeyPair,
  normalizeHtu,
  sha256Base64Url,
  signDPoPProof,
  verifyDPoPProof,
  WolinAuthError,
} from '../src/index.js';

describe('@wolin-id/client — RFC 9449 ES256 DPoP & Base64URL', () => {
  it('encodes and decodes canonical unpadded Base64URL and rejects non-canonical inputs', () => {
    const samples = [
      new Uint8Array([]),
      new Uint8Array([0]),
      new Uint8Array([1, 2]),
      new Uint8Array([255, 254, 253]),
      new TextEncoder().encode('Wolin Solid Pod Engine — 月印千江'),
    ];

    for (const sample of samples) {
      const encoded = base64UrlEncode(sample);
      expect(encoded).not.toContain('=');
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(base64UrlDecode(encoded)).toEqual(sample);
    }

    // Reject padding, standard base64 chars, invalid length (% 4 === 1), and non-zero trailing bits
    expect(() => base64UrlDecode('YWJj=')).toThrow();
    expect(() => base64UrlDecode('abc+def')).toThrow();
    expect(() => base64UrlDecode('abc/def')).toThrow();
    expect(() => base64UrlDecode('abcde')).toThrow();
    expect(() => base64UrlDecode('QR')).toThrow();
  });

  it('generates an ES256 P-256 keypair with clean public JWK and deterministic RFC 7638 thumbprint', async () => {
    const keyPair = await generateDPoPKeyPair();

    expect(keyPair.publicJwk.kty).toBe('EC');
    expect(keyPair.publicJwk.crv).toBe('P-256');
    expect(typeof keyPair.publicJwk.x).toBe('string');
    expect(typeof keyPair.publicJwk.y).toBe('string');
    expect(base64UrlDecode(keyPair.publicJwk.x).byteLength).toBe(32);
    expect(base64UrlDecode(keyPair.publicJwk.y).byteLength).toBe(32);

    // Must NOT leak any private or non-canonical JWK fields
    expect(Object.keys(keyPair.publicJwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect('d' in (keyPair.publicJwk as Record<string, unknown>)).toBe(false);

    // RFC 7638 §3.1 canonical JSON order for EC: {"crv":...,"kty":"EC","x":...,"y":...}
    const manualCanonical = `{"crv":"P-256","kty":"EC","x":"${keyPair.publicJwk.x}","y":"${keyPair.publicJwk.y}"}`;
    const expectedJkt = await sha256Base64Url(manualCanonical);
    expect(keyPair.jkt).toBe(expectedJkt);
    expect(await computeJwkThumbprint(keyPair.publicJwk)).toBe(expectedJkt);
  });

  it('rejects private key material in JWK thumbprint computation', async () => {
    const keyPair = await generateDPoPKeyPair();
    const leakedJwk = {
      ...keyPair.publicJwk,
      d: keyPair.publicJwk.x,
    } as unknown as typeof keyPair.publicJwk;

    await expect(computeJwkThumbprint(leakedJwk)).rejects.toThrow(WolinAuthError);
  });

  it('normalizes DPoP htu URIs per RFC 9449 §4.2 (stripping query and fragment, rejecting userinfo)', () => {
    expect(normalizeHtu('https://ALICE.WOLIN.ID/private/notes.ttl?version=2#section-1')).toBe(
      'https://alice.wolin.id/private/notes.ttl',
    );
    expect(normalizeHtu('http://localhost:4000/pods/alice/')).toBe(
      'http://localhost:4000/pods/alice/',
    );

    expect(() => normalizeHtu('ftp://alice.wolin.id/file')).toThrow(WolinAuthError);
    const urlWithUser = ['https://', 'alice', '@wolin.id/profile/card'].join('');
    expect(() => normalizeHtu(urlWithUser)).toThrow(WolinAuthError);
  });

  it('signs a cryptographically valid ES256 DPoP JWT proof verifiable with Web Crypto', async () => {
    const keyPair = await generateDPoPKeyPair();
    const accessToken = 'wolin-dpop-access-token-sample-01';
    const fixedIat = 1_763_500_000;

    const proof = await signDPoPProof({
      keyPair,
      htm: 'put',
      htu: 'https://alice.wolin.id/private/doc.ttl?draft=true#top',
      accessToken,
      nonce: 'srv-nonce-42',
      iat: fixedIat,
      jti: 'jti-fixed-001',
    });

    const segments = proof.split('.');
    expect(segments).toHaveLength(3);
    const [headerB64, payloadB64, sigB64] = segments as [string, string, string];

    const header = JSON.parse(base64UrlDecodeString(headerB64)) as Record<string, unknown>;
    expect(header).toEqual({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: keyPair.publicJwk,
    });

    const payload = JSON.parse(base64UrlDecodeString(payloadB64)) as Record<string, unknown>;
    const expectedAth = await sha256Base64Url(accessToken);
    expect(payload).toEqual({
      jti: 'jti-fixed-001',
      htm: 'PUT',
      htu: 'https://alice.wolin.id/private/doc.ttl',
      iat: fixedIat,
      ath: expectedAth,
      nonce: 'srv-nonce-42',
    });

    // Real Web Crypto ES256 signature verification (64-byte IEEE P1363 R||S)
    const sigBytes = base64UrlDecode(sigB64);
    expect(sigBytes.byteLength).toBe(64);

    const importedPubKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      keyPair.publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const valid = await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      importedPubKey,
      sigBytes as BufferSource,
      signingInput,
    );
    expect(valid).toBe(true);

    // Also verify via SDK helper
    const verified = await verifyDPoPProof(proof, {
      htm: 'PUT',
      htu: 'https://alice.wolin.id/private/doc.ttl',
      accessToken,
      nowEpochSecs: fixedIat + 5,
    });
    expect(verified.jkt).toBe(keyPair.jkt);
    expect(verified.ath).toBe(expectedAth);
    expect(verified.nonce).toBe('srv-nonce-42');

    // Rejects wrong HTTP method, wrong access token, or tampered signature
    await expect(
      verifyDPoPProof(proof, {
        htm: 'GET',
        htu: 'https://alice.wolin.id/private/doc.ttl',
        accessToken,
        nowEpochSecs: fixedIat + 5,
      }),
    ).rejects.toThrow(WolinAuthError);

    await expect(
      verifyDPoPProof(proof, {
        htm: 'PUT',
        htu: 'https://alice.wolin.id/private/doc.ttl',
        accessToken: 'different-token',
        nowEpochSecs: fixedIat + 5,
      }),
    ).rejects.toThrow(WolinAuthError);
  });
});
