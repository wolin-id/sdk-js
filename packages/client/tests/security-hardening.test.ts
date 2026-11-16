import { describe, expect, it, vi } from 'vitest';
import {
  base64UrlEncode,
  base64UrlEncodeString,
  createSolidAuthRequest,
  discoverOidcProvider,
  exchangeCodeForTokens,
  fetchWebIdProfile,
  generateDPoPKeyPair,
  parseLinkHeaderTypes,
  parseTurtle,
  parseWebIdProfile,
  verifyDPoPProof,
  verifyWebIdOidcIssuer,
  WolinAuthError,
  WolinError,
  WolinParseError,
  WolinPodClient,
} from '../src/index.js';

function makeJwt(claims: Record<string, unknown>): string {
  const hdr = base64UrlEncodeString(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
  const pay = base64UrlEncodeString(JSON.stringify(claims));
  const sig = base64UrlEncodeString('sig-bytes');
  return `${hdr}.${pay}.${sig}`;
}

describe('@wolin-id/client — Security & Protocol Hardening Regression Suite', () => {
  it('verifyDPoPProof rejects non-object JSON header/payload, query/fragment in proof htu, and control chars in jti', async () => {
    const kp = await generateDPoPKeyPair();
    const nullB64 = base64UrlEncodeString('null');
    const arrB64 = base64UrlEncodeString('[]');

    await expect(
      verifyDPoPProof(`${nullB64}.${nullB64}.AAAA`, {
        htm: 'GET',
        htu: 'https://alice.wolin.id/',
      }),
    ).rejects.toThrow(WolinAuthError);

    await expect(
      verifyDPoPProof(`${arrB64}.${arrB64}.AAAA`, {
        htm: 'GET',
        htu: 'https://alice.wolin.id/',
      }),
    ).rejects.toThrow(WolinAuthError);

    // Forge a signed proof whose payload htu contains a query string (forbidden per RFC 9449 §4.2)
    const badHeaderB64 = base64UrlEncodeString(
      JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: kp.publicJwk }),
    );
    const badPayloadB64 = base64UrlEncodeString(
      JSON.stringify({
        jti: 'jti-q',
        htm: 'GET',
        htu: 'https://alice.wolin.id/doc?leak=1',
        iat: 1_763_500_000,
      }),
    );
    const rawSig = await globalThis.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      kp.privateKey,
      new TextEncoder().encode(`${badHeaderB64}.${badPayloadB64}`),
    );
    const sigB64 = base64UrlEncode(new Uint8Array(rawSig));

    await expect(
      verifyDPoPProof(`${badHeaderB64}.${badPayloadB64}.${sigB64}`, {
        htm: 'GET',
        htu: 'https://alice.wolin.id/doc?leak=1',
        nowEpochSecs: 1_763_500_005,
      }),
    ).rejects.toThrow(WolinAuthError);
  });

  it('blocks OIDC discovery fragment/query URL spoofing, HTTP downgrade, empty state, and expired/wrong-issuer tokens', async () => {
    const mockFetch = vi.fn<typeof fetch>();

    // Reject # or ? in issuerUrl before fetching
    await expect(
      discoverOidcProvider('https://auth.wolin.id/pods/evil/fake.json#', { fetchFn: mockFetch }),
    ).rejects.toThrow(WolinAuthError);
    await expect(
      discoverOidcProvider('https://auth.wolin.id?redirect=1', { fetchFn: mockFetch }),
    ).rejects.toThrow(WolinAuthError);
    expect(mockFetch).not.toHaveBeenCalled();

    // Reject HTTPS issuer downgrading token_endpoint to HTTP
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          issuer: 'https://auth.wolin.id',
          authorization_endpoint: 'https://auth.wolin.id/auth',
          token_endpoint: 'http://auth.wolin.id/token',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    await expect(
      discoverOidcProvider('https://auth.wolin.id', { fetchFn: mockFetch }),
    ).rejects.toThrow(WolinAuthError);

    // Reject empty OAuth state
    await expect(
      createSolidAuthRequest({
        authorizationEndpoint: 'https://auth.wolin.id/auth',
        clientId: 'https://app.wolin.id/client',
        redirectUri: 'https://app.wolin.id/cb',
        state: '   ',
      }),
    ).rejects.toThrow(WolinAuthError);

    // Reject expired id_token and malformed id_token during token exchange
    const kp = await generateDPoPKeyPair();
    const expiredIdToken = makeJwt({
      iss: 'https://auth.wolin.id',
      sub: 'alice',
      webid: 'https://alice.wolin.id/profile/card#me',
      aud: 'https://app.wolin.id/client',
      exp: 1_700_000_000,
    });
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'opaque-at',
          token_type: 'dpop',
          id_token: expiredIdToken,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    await expect(
      exchangeCodeForTokens({
        tokenEndpoint: 'https://auth.wolin.id/token',
        code: 'code-1',
        codeVerifier: 'v'.repeat(43),
        redirectUri: 'https://app.wolin.id/cb',
        clientId: 'https://app.wolin.id/client',
        expectedIssuer: 'https://auth.wolin.id',
        nowEpochSecs: 1_800_000_000,
        dpopKeyPair: kp,
        fetchFn: mockFetch,
      }),
    ).rejects.toThrow(WolinAuthError);
  });

  it('blocks Pod origin escape, path traversal (///, \\\\, ../), and cross-origin Authorization exfiltration', async () => {
    const kp = await generateDPoPKeyPair();
    const mockFetch = vi.fn<typeof fetch>();

    const client = new WolinPodClient({
      podUrl: 'https://pod.wolin.id/pods/alice/',
      accessToken: 'secret-dpop-token',
      dpopKeyPair: kp,
      tokenType: 'dpop', // lowercase normalized to 'DPoP'
      fetchFn: mockFetch,
    });

    await expect(client.getResource('///attacker.example/steal')).rejects.toThrow(WolinError);
    await expect(client.getResource('\\\\attacker.example/steal')).rejects.toThrow(WolinError);
    await expect(client.getResource('../bob/secret.ttl')).rejects.toThrow(WolinError);
    await expect(client.getResource('https://attacker.example/collect')).rejects.toThrow(
      WolinAuthError,
    );
    expect(mockFetch).not.toHaveBeenCalled();

    // Conflicting If-Match + createOnly rejected immediately
    await expect(
      client.putResource('/notes.ttl', '<#a> <#b> "c" .', {
        ifMatch: '"etag-1"',
        createOnly: true,
      }),
    ).rejects.toThrow(WolinError);
  });

  it('handles Turtle out-of-range \\U escapes, 4/5-quote multiline strings, blank-node collision, and WebID trust chain', async () => {
    // Out-of-range Unicode scalar throws WolinParseError, never RangeError
    expect(() =>
      parseTurtle('<#s> <#p> "\\U99999999" .', 'https://alice.wolin.id/doc.ttl'),
    ).toThrow(WolinParseError);

    // Bare subject without predicate-object list throws WolinParseError
    expect(() => parseTurtle('<#s> .', 'https://alice.wolin.id/doc.ttl')).toThrow(WolinParseError);

    // 4-quote multiline literal + explicit _:b1 alongside anonymous [] blank node
    const trickyTurtle = `
_:b1 <https://example.org/p> "explicit-b1" .
<#s> <https://example.org/quote> """hello "world"""" ;
     <https://example.org/anon> [ <https://example.org/p> "anon-bnode" ] .
`;
    const triples = parseTurtle(trickyTurtle, 'https://alice.wolin.id/doc.ttl');
    const quoteTriple = triples.find((t) => t.predicate === 'https://example.org/quote');
    expect(quoteTriple?.object).toBe('hello "world"');

    const b1Values = triples.filter((t) => t.subject === '_:b1').map((t) => t.object);
    expect(b1Values).toEqual(['explicit-b1']);

    // Canonical uppercase-host WebID + solid:oidcIssuer verification
    const profile = parseWebIdProfile(
      '<#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <https://auth.wolin.id> .',
      'https://ALICE.WOLIN.ID/profile/card#me',
    );
    expect(() => verifyWebIdOidcIssuer(profile, 'https://auth.wolin.id')).not.toThrow();
    expect(() => verifyWebIdOidcIssuer(profile, 'https://rogue.idp.example')).toThrow(
      WolinAuthError,
    );

    // Rejects HTML Content-Type on fetchWebIdProfile
    const htmlFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
      new Response('<html>login</html>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      }),
    );
    await expect(
      fetchWebIdProfile('https://alice.wolin.id/profile/card#me', { fetchFn: htmlFetch }),
    ).rejects.toThrow(WolinParseError);

    // RFC 8288 Link header parser handles commas inside quoted parameters and IRIs
    const linkTypes = parseLinkHeaderTypes(
      '<http://www.w3.org/ns/ldp#Resource>; title="a, b"; rel="type", <https://example.org/type,2>; rel="type"',
    );
    expect(linkTypes).toEqual([
      'http://www.w3.org/ns/ldp#Resource',
      'https://example.org/type,2',
    ]);
  });

  it('rejects off-curve P-256 JWK, HTTPS->HTTP WebID redirect downgrade, mixed dot-encoding, and keyless DPoP downgrade', async () => {
    // 1. Off-curve 32-byte zero coordinates throw WolinAuthError (not raw DOMException)
    const zeroCoord = base64UrlEncode(new Uint8Array(32));
    const offCurveHdr = base64UrlEncodeString(
      JSON.stringify({
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk: { kty: 'EC', crv: 'P-256', x: zeroCoord, y: zeroCoord },
      }),
    );
    const offCurvePay = base64UrlEncodeString(
      JSON.stringify({ jti: 'j1', htm: 'GET', htu: 'https://alice.wolin.id/', iat: 1_763_500_000 }),
    );
    const fakeSig = base64UrlEncode(new Uint8Array(64));
    await expect(
      verifyDPoPProof(`${offCurveHdr}.${offCurvePay}.${fakeSig}`, {
        htm: 'GET',
        htu: 'https://alice.wolin.id/',
        nowEpochSecs: 1_763_500_000,
      }),
    ).rejects.toThrow(WolinAuthError);

    // 2. HTTPS -> HTTP redirect downgrade on fetchWebIdProfile throws WolinAuthError
    const downgradedResp = new Response('<#me> a <#Person> .', {
      status: 200,
      headers: { 'Content-Type': 'text/turtle' },
    });
    Object.defineProperty(downgradedResp, 'url', {
      value: 'http://alice.wolin.id/profile/card',
    });
    const downgradeFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(downgradedResp);
    await expect(
      fetchWebIdProfile('https://alice.wolin.id/profile/card#me', { fetchFn: downgradeFetch }),
    ).rejects.toThrow(WolinAuthError);

    // 3. Mixed dot-encoding (.%2e / %2e.) rejected & /https://... stays relative under Pod
    const pod = new WolinPodClient({ podUrl: 'https://pod.wolin.id/pods/alice/' });
    expect(() => pod.resolveUrl('/sandbox/.%2e/secret')).toThrow(WolinError);
    expect(() => pod.resolveUrl('/sandbox/%2e./secret')).toThrow(WolinError);
    expect(pod.resolveUrl('/https:/note.ttl')).toBe('https://pod.wolin.id/pods/alice/https:/note.ttl');

    // 4. tokenType: 'DPoP' without dpopKeyPair fails closed instead of downgrading to Bearer
    const keylessDpopPod = new WolinPodClient({
      podUrl: 'https://alice.wolin.id/',
      accessToken: 'dpop-bound-token',
      tokenType: 'DPoP',
      fetchFn: vi.fn<typeof fetch>(),
    });
    await expect(keylessDpopPod.getResource('/private/doc.ttl')).rejects.toThrow(WolinAuthError);
  });
});
