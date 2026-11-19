import { describe, expect, it, vi } from 'vitest';
import {
  base64UrlDecodeString,
  base64UrlEncodeString,
  buildSolidAuthUrl,
  createSolidAuthRequest,
  discoverOidcProvider,
  exchangeCodeForTokens,
  generateDPoPKeyPair,
  generatePkcePair,
  refreshSolidTokens,
  sha256Base64Url,
  WolinAuthError,
} from '../src/index.js';

function buildUnsignedTestJwt(claims: Record<string, unknown>): string {
  const hdr = base64UrlEncodeString(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
  const pay = base64UrlEncodeString(JSON.stringify(claims));
  const sig = base64UrlEncodeString('synthetic-sig-bytes');
  return `${hdr}.${pay}.${sig}`;
}

describe('@wolin-id/client — Solid-OIDC Discovery, PKCE & Token Exchange', () => {
  it('generates valid RFC 7636 S256 PKCE verifier and challenge pairs', async () => {
    const pkce = await generatePkcePair();

    expect(pkce.codeChallengeMethod).toBe('S256');
    expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(pkce.codeVerifier.length).toBeLessThanOrEqual(128);

    const expectedChallenge = await sha256Base64Url(pkce.codeVerifier);
    expect(pkce.codeChallenge).toBe(expectedChallenge);
  });

  it('builds a Solid-OIDC PKCE authorization URL with openid & webid scopes, nonce, and dpop_jkt', async () => {
    const kp = await generateDPoPKeyPair();
    const authReq = await createSolidAuthRequest({
      authorizationEndpoint: 'https://auth.wolin.id/oauth/v2/authorize',
      clientId: 'https://app.wolin.id/client.jsonld',
      redirectUri: 'https://app.wolin.id/auth/callback',
      state: 'state-xyz-123',
      nonce: 'nonce-abc-456',
      dpopJkt: kp.jkt,
      prompt: 'consent',
    });

    const parsed = new URL(authReq.url);
    expect(parsed.origin + parsed.pathname).toBe('https://auth.wolin.id/oauth/v2/authorize');
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('client_id')).toBe('https://app.wolin.id/client.jsonld');
    expect(parsed.searchParams.get('redirect_uri')).toBe('https://app.wolin.id/auth/callback');
    expect(parsed.searchParams.get('code_challenge')).toBe(authReq.codeChallenge);
    expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    expect(parsed.searchParams.get('state')).toBe('state-xyz-123');
    expect(parsed.searchParams.get('nonce')).toBe('nonce-abc-456');
    expect(parsed.searchParams.get('dpop_jkt')).toBe(kp.jkt);
    expect(parsed.searchParams.get('scope')).toBe('openid webid offline_access');
    expect(parsed.searchParams.get('prompt')).toBe('consent');
    expect(authReq.nonce).toBe('nonce-abc-456');
    expect(authReq.dpopJkt).toBe(kp.jkt);

    // Direct buildSolidAuthUrl rejects invalid scheme
    expect(() =>
      buildSolidAuthUrl({
        authorizationEndpoint: 'javascript:alert(1)',
        clientId: 'client-1',
        redirectUri: 'https://app.wolin.id/cb',
        codeChallenge: authReq.codeChallenge,
      }),
    ).toThrow(WolinAuthError);
  });

  it('discovers OIDC provider metadata and enforces issuer match', async () => {
    const mockFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          issuer: 'https://auth.wolin.id',
          authorization_endpoint: 'https://auth.wolin.id/oauth/v2/authorize',
          token_endpoint: 'https://auth.wolin.id/oauth/v2/token',
          dpop_signing_alg_values_supported: ['ES256'],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const metadata = await discoverOidcProvider('https://auth.wolin.id/', { fetchFn: mockFetch });
    expect(mockFetch).toHaveBeenCalledWith(
      'https://auth.wolin.id/.well-known/openid-configuration',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(metadata.token_endpoint).toBe('https://auth.wolin.id/oauth/v2/token');

    // Rejects mismatched issuer in discovery document
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          issuer: 'https://evil.idp.example',
          authorization_endpoint: 'https://evil.idp.example/auth',
          token_endpoint: 'https://evil.idp.example/token',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    await expect(
      discoverOidcProvider('https://auth.wolin.id', { fetchFn: mockFetch }),
    ).rejects.toThrow(WolinAuthError);
  });

  it('exchanges authorization code with DPoP proof and retries automatically on DPoP-Nonce challenge', async () => {
    const dpopKeyPair = await generateDPoPKeyPair();
    const idToken = buildUnsignedTestJwt({
      iss: 'https://auth.wolin.id',
      sub: 'alice-sub',
      webid: 'https://alice.wolin.id/profile/card#me',
      aud: ['https://app.wolin.id/client.jsonld', 'solid'],
      exp: 2_000_000_000,
    });
    const accessToken = buildUnsignedTestJwt({
      iss: 'https://auth.wolin.id',
      sub: 'alice-sub',
      webid: 'https://alice.wolin.id/profile/card#me',
      aud: 'solid',
      cnf: { jkt: dpopKeyPair.jkt },
      exp: 2_000_000_000,
    });

    const mockFetch = vi
      .fn<typeof fetch>()
      // 1st attempt: IdP demands DPoP-Nonce per RFC 9449 §8
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ error: 'use_dpop_nonce' }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'DPoP-Nonce': 'idp-fresh-nonce-99',
          },
        }),
      )
      // 2nd attempt: succeeds with nonce inside DPoP proof
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: accessToken,
            token_type: 'DPoP',
            id_token: idToken,
            refresh_token: 'rt-opaque-01',
            expires_in: 3600,
            scope: 'openid webid offline_access',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

    const tokenSet = await exchangeCodeForTokens({
      tokenEndpoint: 'https://auth.wolin.id/oauth/v2/token',
      code: 'auth-code-777',
      codeVerifier: 'verifier-secret-at-least-43-characters-long-for-pkce-s256',
      redirectUri: 'https://app.wolin.id/auth/callback',
      clientId: 'https://app.wolin.id/client.jsonld',
      dpopKeyPair,
      fetchFn: mockFetch,
    });

    expect(mockFetch).toHaveBeenCalledTimes(2);

    // Inspect second request's DPoP header to confirm nonce & htm/htu
    const secondCallInit = mockFetch.mock.calls[1]?.[1];
    const secondHeaders = new Headers(secondCallInit?.headers);
    const dpopHeader = secondHeaders.get('DPoP')!;
    const [, payloadB64] = dpopHeader.split('.') as [string, string, string];
    const proofPayload = JSON.parse(base64UrlDecodeString(payloadB64)) as Record<string, unknown>;

    expect(proofPayload.htm).toBe('POST');
    expect(proofPayload.htu).toBe('https://auth.wolin.id/oauth/v2/token');
    expect(proofPayload.nonce).toBe('idp-fresh-nonce-99');
    expect(proofPayload.ath).toBeUndefined();

    const formParams = new URLSearchParams(String(secondCallInit?.body));
    expect(formParams.get('grant_type')).toBe('authorization_code');
    expect(formParams.get('code')).toBe('auth-code-777');
    expect(formParams.get('code_verifier')).toBe(
      'verifier-secret-at-least-43-characters-long-for-pkce-s256',
    );

    expect(tokenSet.accessToken).toBe(accessToken);
    expect(tokenSet.tokenType).toBe('DPoP');
    expect(tokenSet.webId).toBe('https://alice.wolin.id/profile/card#me');
    expect(tokenSet.refreshToken).toBe('rt-opaque-01');
    expect(tokenSet.expiresIn).toBe(3600);
  });

  it('refreshes Solid tokens with a DPoP proof bound to the token endpoint', async () => {
    const dpopKeyPair = await generateDPoPKeyPair();
    const newAccessToken = buildUnsignedTestJwt({
      iss: 'https://auth.wolin.id',
      sub: 'https://alice.wolin.id/profile/card#me',
      aud: 'solid',
      cnf: { jkt: dpopKeyPair.jkt },
      exp: 2_000_003_600,
    });

    const mockFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: newAccessToken,
          token_type: 'DPoP',
          expires_in: 3600,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const refreshed = await refreshSolidTokens({
      tokenEndpoint: 'https://auth.wolin.id/oauth/v2/token',
      refreshToken: 'rt-opaque-01',
      clientId: 'https://app.wolin.id/client.jsonld',
      dpopKeyPair,
      fetchFn: mockFetch,
    });

    expect(refreshed.accessToken).toBe(newAccessToken);
    expect(refreshed.webId).toBe('https://alice.wolin.id/profile/card#me');
  });
});
