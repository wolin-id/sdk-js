import {
  base64UrlDecode,
  base64UrlDecodeString,
  base64UrlEncode,
  base64UrlEncodeString,
  getWebCrypto,
  sha256Base64Url,
} from './base64url.js';
import { WolinAuthError } from './errors.js';

const FORBIDDEN_PRIVATE_JWK_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;
const MAX_DPOP_URI_LEN = 2048;
const DEFAULT_MAX_SKEW_SECS = 300;

export type DPoPPublicJwk = {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
};

export interface DPoPKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: DPoPPublicJwk;
  jkt: string;
}

export interface GenerateDPoPKeyPairOptions {
  /**
   * Whether the private CryptoKey should be extractable.
   * Defaults to `false` so private key material remains non-extractable in Web Crypto.
   */
  extractable?: boolean;
}

export interface SignDPoPProofOptions {
  keyPair: DPoPKeyPair;
  htm: string;
  htu: string;
  accessToken?: string;
  nonce?: string;
  iat?: number;
  jti?: string;
}

export interface VerifiedDPoPProof {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  ath?: string;
  nonce?: string;
  jkt: string;
  publicJwk: DPoPPublicJwk;
}

export interface VerifyDPoPProofOptions {
  htm: string;
  htu: string;
  accessToken?: string;
  nowEpochSecs?: number;
  maxSkewSecs?: number;
}

function isPlainRecord(val: unknown): val is Record<string, unknown> {
  return Boolean(val) && typeof val === 'object' && !Array.isArray(val);
}

function validateEcP256PublicJwk(jwk: unknown): DPoPPublicJwk {
  if (!isPlainRecord(jwk)) {
    throw new WolinAuthError('DPoP public JWK must be a JSON object');
  }
  for (const field of FORBIDDEN_PRIVATE_JWK_FIELDS) {
    if (field in jwk) {
      throw new WolinAuthError(`DPoP public JWK must not contain private field '${field}'`);
    }
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new WolinAuthError('ES256 DPoP JWK requires kty "EC" and crv "P-256"');
  }
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || !jwk.x || !jwk.y) {
    throw new WolinAuthError('ES256 DPoP JWK requires non-empty "x" and "y" coordinates');
  }
  const xBytes = base64UrlDecode(jwk.x);
  const yBytes = base64UrlDecode(jwk.y);
  if (xBytes.byteLength !== 32 || yBytes.byteLength !== 32) {
    throw new WolinAuthError('ES256 P-256 JWK coordinates must each decode to 32 bytes');
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: jwk.x,
    y: jwk.y,
  };
}

/**
 * Compute an RFC 7638 §3.1 canonical SHA-256 JWK Thumbprint (unpadded Base64URL)
 * for an ES256 (`P-256`) public JWK.
 */
export async function computeJwkThumbprint(jwk: DPoPPublicJwk): Promise<string> {
  const clean = validateEcP256PublicJwk(jwk);
  const canonicalJson = `{"crv":${JSON.stringify(clean.crv)},"kty":"EC","x":${JSON.stringify(
    clean.x,
  )},"y":${JSON.stringify(clean.y)}}`;
  return sha256Base64Url(canonicalJson);
}

/**
 * Generate a fresh ES256 (ECDSA P-256) keypair using Web Crypto API and precompute
 * its sanitized public JWK and RFC 7638 `jkt` thumbprint.
 */
export async function generateDPoPKeyPair(
  options?: GenerateDPoPKeyPairOptions,
): Promise<DPoPKeyPair> {
  const cryptoObj = getWebCrypto();
  const extractable = options?.extractable ?? false;

  const generated = await cryptoObj.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    extractable,
    ['sign', 'verify'],
  );

  const exportedPub = await cryptoObj.subtle.exportKey('jwk', generated.publicKey);
  const publicJwk: DPoPPublicJwk = validateEcP256PublicJwk({
    kty: exportedPub.kty,
    crv: exportedPub.crv,
    x: exportedPub.x,
    y: exportedPub.y,
  });
  const jkt = await computeJwkThumbprint(publicJwk);

  return {
    privateKey: generated.privateKey,
    publicKey: generated.publicKey,
    publicJwk,
    jkt,
  };
}

/**
 * Normalize an HTTP(S) URI for RFC 9449 §4.2 `htu` claims:
 * - Validates `http:` or `https:` scheme
 * - Rejects embedded userinfo credentials and backslashes
 * - Strips query (`?...`) and fragment (`#...`) components
 * - Lowercases scheme and host authority
 */
export function normalizeHtu(rawUrl: string): string {
  if (!rawUrl || rawUrl.length > MAX_DPOP_URI_LEN || /[\s\x00-\x1f\x7f\\]/.test(rawUrl)) {
    throw new WolinAuthError('DPoP htu must be a valid HTTP(S) URI');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new WolinAuthError(`Malformed DPoP htu URI '${rawUrl}'`, { cause: err });
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new WolinAuthError(`DPoP htu requires http or https scheme (got '${parsed.protocol}')`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new WolinAuthError('Userinfo credentials are forbidden in DPoP htu URIs');
  }
  if (!parsed.hostname) {
    throw new WolinAuthError('Missing host authority in DPoP htu URI');
  }

  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

/**
 * Sign an RFC 9449 ES256 DPoP proof JWT bound to `htm`, `htu`, and optional `accessToken` (`ath`).
 */
export async function signDPoPProof(options: SignDPoPProofOptions): Promise<string> {
  const cryptoObj = getWebCrypto();
  const publicJwk = validateEcP256PublicJwk(options.keyPair.publicJwk);

  const htm = options.htm.trim().toUpperCase();
  if (!htm || !/^[A-Z]+$/.test(htm)) {
    throw new WolinAuthError(`Invalid HTTP method '${options.htm}' for DPoP htm claim`);
  }

  const htu = normalizeHtu(options.htu);
  const jti = options.jti ?? cryptoObj.randomUUID();
  if (!jti.trim() || jti.length > 256 || /[\x00-\x1f\x7f]/.test(jti)) {
    throw new WolinAuthError('Invalid DPoP jti claim');
  }

  const iat = options.iat ?? Math.floor(Date.now() / 1000);
  if (!Number.isInteger(iat) || iat <= 0) {
    throw new WolinAuthError('DPoP iat claim must be a positive integer epoch timestamp');
  }

  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: publicJwk,
  };

  const payload: Record<string, unknown> = {
    jti,
    htm,
    htu,
    iat,
  };

  if (options.accessToken !== undefined) {
    if (!options.accessToken.trim()) {
      throw new WolinAuthError('DPoP accessToken must not be empty when provided');
    }
    payload.ath = await sha256Base64Url(options.accessToken);
  }

  if (options.nonce !== undefined) {
    if (!options.nonce.trim()) {
      throw new WolinAuthError('DPoP nonce must not be empty when provided');
    }
    payload.nonce = options.nonce;
  }

  const headerB64 = base64UrlEncodeString(JSON.stringify(header));
  const payloadB64 = base64UrlEncodeString(JSON.stringify(payload));
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const rawSig = await cryptoObj.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    options.keyPair.privateKey,
    signingInput,
  );
  const sigB64 = base64UrlEncode(new Uint8Array(rawSig));

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

/**
 * Cryptographically verify an ES256 RFC 9449 DPoP proof JWT using Web Crypto API.
 */
export async function verifyDPoPProof(
  dpopJwt: string,
  options: VerifyDPoPProofOptions,
): Promise<VerifiedDPoPProof> {
  const cryptoObj = getWebCrypto();
  if (!dpopJwt || dpopJwt.length > 8192 || /[\s\x00-\x1f\x7f]/.test(dpopJwt)) {
    throw new WolinAuthError('Malformed or oversized DPoP proof JWT');
  }

  const parts = dpopJwt.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new WolinAuthError('Invalid compact DPoP JWT format');
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let parsedHeader: unknown;
  try {
    parsedHeader = JSON.parse(base64UrlDecodeString(headerB64));
  } catch (err) {
    throw new WolinAuthError('Malformed DPoP JWT header JSON', { cause: err });
  }
  if (!isPlainRecord(parsedHeader)) {
    throw new WolinAuthError('DPoP JWT header must be a JSON object');
  }

  if ('crit' in parsedHeader) {
    throw new WolinAuthError("Unsupported 'crit' extension in DPoP JWT header");
  }
  if (typeof parsedHeader.typ !== 'string' || parsedHeader.typ.trim().toLowerCase() !== 'dpop+jwt') {
    throw new WolinAuthError("Invalid DPoP header typ: expected 'dpop+jwt'");
  }
  if (parsedHeader.alg !== 'ES256') {
    throw new WolinAuthError(
      `Unsupported DPoP alg '${String(parsedHeader.alg)}': expected 'ES256'`,
    );
  }

  const publicJwk = validateEcP256PublicJwk(parsedHeader.jwk);
  const sigBytes = base64UrlDecode(sigB64);
  if (sigBytes.byteLength !== 64) {
    throw new WolinAuthError('Invalid ES256 DPoP signature byte length');
  }

  let publicKey: CryptoKey;
  let verified: boolean;
  try {
    publicKey = await cryptoObj.subtle.importKey(
      'jwk',
      publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    verified = await cryptoObj.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBytes as BufferSource,
      signingInput,
    );
  } catch (err) {
    throw new WolinAuthError('Invalid or off-curve ES256 DPoP public key', { cause: err });
  }
  if (!verified) {
    throw new WolinAuthError('DPoP ES256 cryptographic signature verification failed');
  }

  let parsedPayload: unknown;
  try {
    parsedPayload = JSON.parse(base64UrlDecodeString(payloadB64));
  } catch (err) {
    throw new WolinAuthError('Malformed DPoP JWT payload JSON', { cause: err });
  }
  if (!isPlainRecord(parsedPayload)) {
    throw new WolinAuthError('DPoP JWT payload must be a JSON object');
  }

  const jti = parsedPayload.jti;
  if (
    typeof jti !== 'string' ||
    !jti.trim() ||
    jti.length > 256 ||
    /[\x00-\x1f\x7f]/.test(jti)
  ) {
    throw new WolinAuthError("Invalid or missing DPoP 'jti' claim");
  }

  const htm = parsedPayload.htm;
  if (typeof htm !== 'string' || htm.toUpperCase() !== options.htm.trim().toUpperCase()) {
    throw new WolinAuthError(
      `DPoP 'htm' mismatch: expected '${options.htm.toUpperCase()}', got '${String(htm)}'`,
    );
  }

  const htu = parsedPayload.htu;
  if (typeof htu !== 'string' || htu.includes('?') || htu.includes('#')) {
    throw new WolinAuthError(
      "DPoP 'htu' claim must be an HTTP(S) URI without query or fragment components",
    );
  }
  const normalizedProofHtu = normalizeHtu(htu);
  if (normalizedProofHtu !== normalizeHtu(options.htu)) {
    throw new WolinAuthError(`DPoP 'htu' mismatch: got '${htu}'`);
  }

  const iat = parsedPayload.iat;
  if (typeof iat !== 'number' || !Number.isInteger(iat)) {
    throw new WolinAuthError("Invalid or missing DPoP 'iat' claim");
  }
  const now = options.nowEpochSecs ?? Math.floor(Date.now() / 1000);
  const skew = Math.max(1, options.maxSkewSecs ?? DEFAULT_MAX_SKEW_SECS);
  if (iat < now - skew || iat > now + skew) {
    throw new WolinAuthError("DPoP proof 'iat' timestamp is outside freshness window");
  }

  let ath: string | undefined;
  if (options.accessToken !== undefined) {
    if (!options.accessToken.trim()) {
      throw new WolinAuthError('DPoP accessToken must not be empty when provided');
    }
    if (typeof parsedPayload.ath !== 'string' || !parsedPayload.ath.trim()) {
      throw new WolinAuthError("DPoP proof missing required RFC 9449 'ath' claim");
    }
    const expectedAth = await sha256Base64Url(options.accessToken);
    if (parsedPayload.ath !== expectedAth) {
      throw new WolinAuthError("DPoP proof 'ath' claim does not match access token");
    }
    ath = parsedPayload.ath;
  } else if ('ath' in parsedPayload && parsedPayload.ath !== undefined) {
    if (typeof parsedPayload.ath !== 'string' || !parsedPayload.ath.trim()) {
      throw new WolinAuthError("DPoP proof 'ath' claim must be a non-empty string");
    }
    ath = parsedPayload.ath;
  }

  const jkt = await computeJwkThumbprint(publicJwk);
  let nonce: string | undefined;
  if ('nonce' in parsedPayload && parsedPayload.nonce !== undefined) {
    if (typeof parsedPayload.nonce !== 'string' || !parsedPayload.nonce.trim()) {
      throw new WolinAuthError("DPoP proof 'nonce' claim must be a non-empty string");
    }
    nonce = parsedPayload.nonce;
  }

  return {
    jti,
    htm,
    htu: normalizedProofHtu,
    iat,
    ath,
    nonce,
    jkt,
    publicJwk,
  };
}
