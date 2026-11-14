import {
  base64UrlDecodeString,
  base64UrlEncode,
  getWebCrypto,
  sha256Base64Url,
} from './base64url.js';
import { type DPoPKeyPair, signDPoPProof } from './dpop.js';
import { WolinAuthError } from './errors.js';

export const DEFAULT_SOLID_OIDC_SCOPES = ['openid', 'webid', 'offline_access'] as const;
const DEFAULT_CLOCK_SKEW_SECS = 60;

export interface OidcProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri?: string;
  registration_endpoint?: string;
  end_session_endpoint?: string;
  dpop_signing_alg_values_supported?: string[];
  code_challenge_methods_supported?: string[];
  scopes_supported?: string[];
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

export interface BuildSolidAuthUrlOptions {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  nonce?: string;
  scopes?: readonly string[];
  prompt?: string;
  extraParams?: Record<string, string>;
}

export interface CreateSolidAuthRequestOptions
  extends Omit<BuildSolidAuthUrlOptions, 'codeChallenge'> {
  pkceByteLength?: number;
}

export interface SolidAuthRequest {
  url: string;
  state: string;
  codeVerifier: string;
  codeChallenge: string;
  clientId: string;
  redirectUri: string;
}

export interface TokenExchangeOptions {
  tokenEndpoint: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientId: string;
  clientSecret?: string;
  expectedIssuer?: string;
  nowEpochSecs?: number;
  clockSkewSecs?: number;
  dpopKeyPair: DPoPKeyPair;
  fetchFn?: typeof fetch;
}

export interface RefreshTokenOptions {
  tokenEndpoint: string;
  refreshToken: string;
  clientId: string;
  clientSecret?: string;
  scopes?: readonly string[];
  expectedIssuer?: string;
  nowEpochSecs?: number;
  clockSkewSecs?: number;
  dpopKeyPair: DPoPKeyPair;
  fetchFn?: typeof fetch;
}

export interface SolidTokenSet {
  accessToken: string;
  tokenType: 'DPoP' | 'Bearer';
  idToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  expiresAt?: number;
  scope?: string;
  webId?: string;
  dpopNonce?: string;
}

function assertValidHttpUrl(rawUrl: string, label: string): URL {
  if (!rawUrl || /[\s\x00-\x1f\x7f\\]/.test(rawUrl)) {
    throw new WolinAuthError(`Malformed ${label} URL '${rawUrl}'`);
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new WolinAuthError(`Malformed ${label} URL '${rawUrl}'`, { cause: err });
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new WolinAuthError(`${label} requires http or https scheme (got '${parsed.protocol}')`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new WolinAuthError(`Userinfo credentials are forbidden in ${label}`);
  }
  return parsed;
}

function assertValidIssuerUrl(rawUrl: string, label: string): URL {
  const parsed = assertValidHttpUrl(rawUrl, label);
  if (rawUrl.includes('?') || rawUrl.includes('#') || parsed.search !== '' || parsed.hash !== '') {
    throw new WolinAuthError(`${label} must not contain query or fragment components`);
  }
  return parsed;
}

function normalizeIssuer(issuer: string): string {
  const parsed = assertValidIssuerUrl(issuer.trim(), 'OIDC issuer');
  const full = parsed.toString();
  return full.replace(/\/+$/, '');
}

export function normalizeAuthTokenType(raw: string): 'DPoP' | 'Bearer' {
  const lower = raw.trim().toLowerCase();
  if (lower === 'dpop') return 'DPoP';
  if (lower === 'bearer') return 'Bearer';
  throw new WolinAuthError(`Unsupported OAuth token_type '${raw}': expected 'DPoP' or 'Bearer'`);
}

/**
 * Generate cryptographically random state string (unpadded Base64URL).
 */
export function generateRandomState(byteLength = 24): string {
  if (!Number.isInteger(byteLength) || byteLength < 16 || byteLength > 96) {
    throw new WolinAuthError('State byteLength must be between 16 and 96');
  }
  const cryptoObj = getWebCrypto();
  const buf = new Uint8Array(byteLength);
  cryptoObj.getRandomValues(buf);
  return base64UrlEncode(buf);
}

/**
 * Generate an RFC 7636 PKCE `S256` `codeVerifier` and `codeChallenge` pair.
 */
export async function generatePkcePair(byteLength = 32): Promise<PkcePair> {
  if (!Number.isInteger(byteLength) || byteLength < 32 || byteLength > 96) {
    throw new WolinAuthError('PKCE byteLength must be between 32 and 96 bytes');
  }
  const cryptoObj = getWebCrypto();
  const randomBytes = new Uint8Array(byteLength);
  cryptoObj.getRandomValues(randomBytes);

  const codeVerifier = base64UrlEncode(randomBytes);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
}

function resolveFetch(customFetch?: typeof fetch): typeof fetch {
  return customFetch
    ? (input, init) => customFetch(input, init)
    : (input, init) => globalThis.fetch(input, init);
}

/**
 * Discover Solid-OIDC provider metadata from `<issuer>/.well-known/openid-configuration`
 * and verify that the returned `issuer` and endpoints match security invariants.
 */
export async function discoverOidcProvider(
  issuerUrl: string,
  options?: { fetchFn?: typeof fetch },
): Promise<OidcProviderMetadata> {
  const fetchImpl = resolveFetch(options?.fetchFn);
  const parsedIssuer = assertValidIssuerUrl(issuerUrl.trim(), 'OIDC issuer');
  const base = parsedIssuer.toString().replace(/\/+$/, '');
  const discoveryUrl = `${base}/.well-known/openid-configuration`;

  const response = await fetchImpl(discoveryUrl, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new WolinAuthError(
      `OIDC discovery failed with HTTP ${response.status} at ${discoveryUrl}`,
    );
  }

  let metadata: OidcProviderMetadata;
  try {
    const rawJson = (await response.json()) as unknown;
    if (!rawJson || typeof rawJson !== 'object' || Array.isArray(rawJson)) {
      throw new WolinAuthError('OIDC discovery metadata must be a JSON object');
    }
    metadata = rawJson as OidcProviderMetadata;
  } catch (err) {
    if (err instanceof WolinAuthError) throw err;
    throw new WolinAuthError('Malformed JSON in OIDC discovery metadata', { cause: err });
  }

  if (typeof metadata.issuer !== 'string' || normalizeIssuer(metadata.issuer) !== base) {
    throw new WolinAuthError(
      `OIDC discovery issuer mismatch: expected '${base}', got '${String(metadata.issuer)}'`,
    );
  }
  if (
    typeof metadata.authorization_endpoint !== 'string' ||
    typeof metadata.token_endpoint !== 'string'
  ) {
    throw new WolinAuthError(
      'OIDC discovery document missing authorization_endpoint or token_endpoint',
    );
  }

  const authEp = assertValidHttpUrl(metadata.authorization_endpoint, 'authorization_endpoint');
  const tokenEp = assertValidIssuerUrl(metadata.token_endpoint, 'token_endpoint');
  if (authEp.hash !== '') {
    throw new WolinAuthError('authorization_endpoint must not contain a URL fragment');
  }
  if (parsedIssuer.protocol === 'https:') {
    if (authEp.protocol !== 'https:' || tokenEp.protocol !== 'https:') {
      throw new WolinAuthError(
        'HTTPS OIDC issuer must not downgrade authorization_endpoint or token_endpoint to cleartext HTTP',
      );
    }
  }

  return metadata;
}

/**
 * Build a Solid-OIDC authorization URL with PKCE S256 parameters.
 */
export function buildSolidAuthUrl(options: BuildSolidAuthUrlOptions): string {
  const authUrl = assertValidHttpUrl(options.authorizationEndpoint, 'authorizationEndpoint');
  if (authUrl.hash !== '') {
    throw new WolinAuthError('authorizationEndpoint must not contain a URL fragment');
  }
  assertValidHttpUrl(options.redirectUri, 'redirectUri');

  if (!options.clientId.trim()) {
    throw new WolinAuthError('clientId must not be empty');
  }
  if (!options.codeChallenge.trim()) {
    throw new WolinAuthError('codeChallenge must not be empty');
  }
  if (options.state !== undefined && !options.state.trim()) {
    throw new WolinAuthError('OAuth state parameter must not be empty when provided');
  }

  const scopes =
    options.scopes && options.scopes.length > 0 ? options.scopes : DEFAULT_SOLID_OIDC_SCOPES;

  if (options.extraParams) {
    for (const [k, v] of Object.entries(options.extraParams)) {
      authUrl.searchParams.set(k, v);
    }
  }

  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', options.clientId.trim());
  authUrl.searchParams.set('redirect_uri', options.redirectUri.trim());
  authUrl.searchParams.set('scope', scopes.join(' '));
  authUrl.searchParams.set('code_challenge', options.codeChallenge.trim());
  authUrl.searchParams.set('code_challenge_method', 'S256');

  if (options.state !== undefined) {
    authUrl.searchParams.set('state', options.state.trim());
  }
  if (options.nonce) {
    authUrl.searchParams.set('nonce', options.nonce);
  }
  if (options.prompt) {
    authUrl.searchParams.set('prompt', options.prompt);
  }

  return authUrl.toString();
}

/**
 * Generate a PKCE S256 pair, CSRF `state`, and Solid-OIDC authorization URL in one step.
 */
export async function createSolidAuthRequest(
  options: CreateSolidAuthRequestOptions,
): Promise<SolidAuthRequest> {
  if (options.state !== undefined && !options.state.trim()) {
    throw new WolinAuthError('OAuth state parameter must not be empty');
  }
  const pkce = await generatePkcePair(options.pkceByteLength ?? 32);
  const state = options.state !== undefined ? options.state.trim() : generateRandomState(24);
  const url = buildSolidAuthUrl({
    ...options,
    state,
    codeChallenge: pkce.codeChallenge,
  });

  return {
    url,
    state,
    codeVerifier: pkce.codeVerifier,
    codeChallenge: pkce.codeChallenge,
    clientId: options.clientId.trim(),
    redirectUri: options.redirectUri.trim(),
  };
}

/**
 * Decode a compact JWT payload without verifying its cryptographic signature
 * (intended for client-side claim inspection of tokens received directly over TLS from the IdP).
 */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new WolinAuthError('Invalid compact JWT format');
  }
  try {
    const parsed = JSON.parse(base64UrlDecodeString(parts[1])) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new WolinAuthError('JWT payload must be a JSON object');
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof WolinAuthError) throw err;
    throw new WolinAuthError('Malformed JWT payload JSON', { cause: err });
  }
}

interface TokenClaimValidationContext {
  clientId: string;
  expectedIssuer?: string;
  expectedJkt?: string;
  tokenType: 'DPoP' | 'Bearer';
  nowEpochSecs: number;
  clockSkewSecs: number;
}

function validateJwtClaimsObject(
  claims: Record<string, unknown>,
  ctx: TokenClaimValidationContext,
  isIdToken: boolean,
): string | undefined {
  if (typeof claims.iss !== 'string' || !claims.iss.trim()) {
    throw new WolinAuthError(`Solid-OIDC ${isIdToken ? 'id_token' : 'token'} missing 'iss' claim`);
  }
  const normalizedClaimIss = normalizeIssuer(claims.iss);
  if (ctx.expectedIssuer && normalizedClaimIss !== normalizeIssuer(ctx.expectedIssuer)) {
    throw new WolinAuthError(
      `Solid-OIDC issuer mismatch: expected '${ctx.expectedIssuer}', got '${claims.iss}'`,
    );
  }

  const audRaw = claims.aud;
  const audList =
    typeof audRaw === 'string'
      ? [audRaw]
      : Array.isArray(audRaw) && audRaw.every((a): a is string => typeof a === 'string')
        ? audRaw
        : [];
  if (audList.length === 0) {
    throw new WolinAuthError(`Solid-OIDC ${isIdToken ? 'id_token' : 'token'} missing 'aud' claim`);
  }
  if (isIdToken) {
    if (!audList.includes(ctx.clientId)) {
      throw new WolinAuthError(
        `Solid-OIDC id_token audience does not include client_id '${ctx.clientId}'`,
      );
    }
  } else if (!audList.includes(ctx.clientId) && !audList.includes('solid')) {
    throw new WolinAuthError(
      `Solid-OIDC access_token audience must include '${ctx.clientId}' or 'solid'`,
    );
  }

  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) {
    throw new WolinAuthError(`Solid-OIDC ${isIdToken ? 'id_token' : 'token'} missing 'exp' claim`);
  }
  if (ctx.nowEpochSecs >= claims.exp + ctx.clockSkewSecs) {
    throw new WolinAuthError(`Solid-OIDC ${isIdToken ? 'id_token' : 'token'} has expired`);
  }
  if (typeof claims.nbf === 'number' && ctx.nowEpochSecs + ctx.clockSkewSecs < claims.nbf) {
    throw new WolinAuthError('Solid-OIDC token is not yet valid (nbf)');
  }
  if (typeof claims.iat === 'number') {
    if (claims.exp <= claims.iat) {
      throw new WolinAuthError('Solid-OIDC token exp must be greater than iat');
    }
    if (claims.iat > ctx.nowEpochSecs + ctx.clockSkewSecs) {
      throw new WolinAuthError('Solid-OIDC token iat is in the future');
    }
  }

  if (!isIdToken && ctx.tokenType === 'DPoP' && ctx.expectedJkt && claims.cnf !== undefined) {
    if (!claims.cnf || typeof claims.cnf !== 'object' || Array.isArray(claims.cnf)) {
      throw new WolinAuthError("Invalid 'cnf' confirmation claim in DPoP access token");
    }
    const cnfObj = claims.cnf as Record<string, unknown>;
    if (typeof cnfObj.jkt === 'string' && cnfObj.jkt !== ctx.expectedJkt) {
      throw new WolinAuthError("DPoP access token 'cnf.jkt' does not match client DPoP keypair");
    }
  }

  if (typeof claims.webid === 'string' && claims.webid.trim()) {
    const rawWebId = claims.webid.trim();
    if (!/^(https?:\/\/|did:)/i.test(rawWebId)) {
      throw new WolinAuthError(`Solid-OIDC 'webid' claim must be an HTTP(S) or DID URI`);
    }
    return rawWebId;
  }
  if (typeof claims.sub === 'string' && /^(https?:\/\/|did:)/i.test(claims.sub.trim())) {
    return claims.sub.trim();
  }
  return undefined;
}

function validateAndExtractPrincipal(
  idToken: string | undefined,
  accessToken: string,
  ctx: TokenClaimValidationContext,
): string | undefined {
  let idTokenWebId: string | undefined;
  if (idToken !== undefined) {
    // id_token in OIDC MUST be a valid compact JWT; never swallow parse errors!
    const idClaims = decodeJwtPayload(idToken);
    idTokenWebId = validateJwtClaimsObject(idClaims, ctx, true);
  }

  let accessTokenWebId: string | undefined;
  if (accessToken.split('.').length === 3) {
    let accessClaims: Record<string, unknown> | undefined;
    try {
      accessClaims = decodeJwtPayload(accessToken);
    } catch {
      // Opaque 3-segment tokens are rare; ignore non-JWT opaque tokens
      accessClaims = undefined;
    }
    if (accessClaims && ('iss' in accessClaims || 'exp' in accessClaims || 'webid' in accessClaims)) {
      accessTokenWebId = validateJwtClaimsObject(accessClaims, ctx, false);
    }
  }

  if (idTokenWebId && accessTokenWebId && idTokenWebId !== accessTokenWebId) {
    throw new WolinAuthError(
      `WebID principal mismatch between id_token ('${idTokenWebId}') and access_token ('${accessTokenWebId}')`,
    );
  }

  return idTokenWebId ?? accessTokenWebId;
}

async function postTokenRequestWithDPoP(
  tokenEndpoint: string,
  formBody: URLSearchParams,
  dpopKeyPair: DPoPKeyPair,
  fetchImpl: typeof fetch,
  claimCtx: Omit<TokenClaimValidationContext, 'tokenType' | 'expectedJkt'>,
): Promise<SolidTokenSet> {
  assertValidIssuerUrl(tokenEndpoint, 'tokenEndpoint');

  const sendOnce = async (nonce?: string): Promise<Response> => {
    const dpopProof = await signDPoPProof({
      keyPair: dpopKeyPair,
      htm: 'POST',
      htu: tokenEndpoint,
      nonce,
    });
    return fetchImpl(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        DPoP: dpopProof,
      },
      body: formBody.toString(),
    });
  };

  let response = await sendOnce();

  // RFC 9449 §8: Authorization Server DPoP-Nonce challenge retry
  if (response.status === 400 || response.status === 401) {
    const serverNonce = response.headers.get('DPoP-Nonce');
    if (serverNonce) {
      let shouldRetry = false;
      const wwwAuth = response.headers.get('WWW-Authenticate') ?? '';
      if (wwwAuth.includes('use_dpop_nonce')) {
        shouldRetry = true;
      } else {
        try {
          const errJson = (await response.clone().json()) as Record<string, unknown>;
          if (errJson.error === 'use_dpop_nonce') {
            shouldRetry = true;
          }
        } catch {
          // Non-JSON error body
        }
      }

      if (shouldRetry) {
        response = await sendOnce(serverNonce);
      }
    }
  }

  if (!response.ok) {
    const errText = await response.text().catch(() => '');
    throw new WolinAuthError(
      `Solid-OIDC token request failed with HTTP ${response.status}${
        errText ? `: ${errText.slice(0, 256)}` : ''
      }`,
    );
  }

  let raw: Record<string, unknown>;
  try {
    const parsed = (await response.json()) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new WolinAuthError('Solid-OIDC token response must be a JSON object');
    }
    raw = parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof WolinAuthError) throw err;
    throw new WolinAuthError('Malformed JSON in Solid-OIDC token response', { cause: err });
  }

  if (typeof raw.access_token !== 'string' || !raw.access_token.trim()) {
    throw new WolinAuthError('Token response missing required access_token');
  }

  const tokenType =
    typeof raw.token_type === 'string' ? normalizeAuthTokenType(raw.token_type) : 'DPoP';
  if (raw.id_token !== undefined && typeof raw.id_token !== 'string') {
    throw new WolinAuthError('Token response id_token must be a compact JWT string');
  }
  const idToken = raw.id_token;
  const refreshToken = typeof raw.refresh_token === 'string' ? raw.refresh_token : undefined;
  const expiresIn =
    typeof raw.expires_in === 'number' && Number.isFinite(raw.expires_in)
      ? raw.expires_in
      : undefined;
  const expiresAt =
    expiresIn !== undefined ? Date.now() + Math.max(0, expiresIn) * 1000 : undefined;
  const scope = typeof raw.scope === 'string' ? raw.scope : undefined;
  const dpopNonce = response.headers.get('DPoP-Nonce') ?? undefined;

  const webId = validateAndExtractPrincipal(idToken, raw.access_token, {
    ...claimCtx,
    tokenType,
    expectedJkt: dpopKeyPair.jkt,
  });

  return {
    accessToken: raw.access_token,
    tokenType,
    idToken,
    refreshToken,
    expiresIn,
    expiresAt,
    scope,
    webId,
    dpopNonce,
  };
}

/**
 * Exchange an OAuth 2.0 / Solid-OIDC authorization code + PKCE `codeVerifier`
 * for a DPoP-bound `SolidTokenSet`.
 */
export async function exchangeCodeForTokens(
  options: TokenExchangeOptions,
): Promise<SolidTokenSet> {
  if (!options.code.trim() || !options.codeVerifier.trim() || !options.clientId.trim()) {
    throw new WolinAuthError('code, codeVerifier, and clientId are required for token exchange');
  }
  assertValidHttpUrl(options.redirectUri, 'redirectUri');

  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: options.code.trim(),
    redirect_uri: options.redirectUri.trim(),
    client_id: options.clientId.trim(),
    code_verifier: options.codeVerifier.trim(),
  });
  if (options.clientSecret) {
    params.set('client_secret', options.clientSecret);
  }

  const fetchImpl = resolveFetch(options.fetchFn);
  return postTokenRequestWithDPoP(
    options.tokenEndpoint,
    params,
    options.dpopKeyPair,
    fetchImpl,
    {
      clientId: options.clientId.trim(),
      expectedIssuer: options.expectedIssuer,
      nowEpochSecs: options.nowEpochSecs ?? Math.floor(Date.now() / 1000),
      clockSkewSecs: Math.max(0, options.clockSkewSecs ?? DEFAULT_CLOCK_SKEW_SECS),
    },
  );
}

/**
 * Refresh a DPoP-bound Solid-OIDC session using a `refresh_token`.
 */
export async function refreshSolidTokens(options: RefreshTokenOptions): Promise<SolidTokenSet> {
  if (!options.refreshToken.trim() || !options.clientId.trim()) {
    throw new WolinAuthError('refreshToken and clientId are required for token refresh');
  }

  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: options.refreshToken.trim(),
    client_id: options.clientId.trim(),
  });
  if (options.clientSecret) {
    params.set('client_secret', options.clientSecret);
  }
  if (options.scopes && options.scopes.length > 0) {
    params.set('scope', options.scopes.join(' '));
  }

  const fetchImpl = resolveFetch(options.fetchFn);
  return postTokenRequestWithDPoP(
    options.tokenEndpoint,
    params,
    options.dpopKeyPair,
    fetchImpl,
    {
      clientId: options.clientId.trim(),
      expectedIssuer: options.expectedIssuer,
      nowEpochSecs: options.nowEpochSecs ?? Math.floor(Date.now() / 1000),
      clockSkewSecs: Math.max(0, options.clockSkewSecs ?? DEFAULT_CLOCK_SKEW_SECS),
    },
  );
}
