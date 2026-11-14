import { WolinAuthError } from './errors.js';

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function getWebCrypto(): Crypto {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj?.subtle) {
    throw new WolinAuthError(
      'Web Crypto API (globalThis.crypto.subtle) is required (Browser or Node.js 20+)',
    );
  }
  return cryptoObj;
}

/**
 * Encode raw bytes to unpadded RFC 4648 §5 Base64URL.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  const len = bytes.byteLength;

  while (i + 3 <= len) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1]!;
    const b2 = bytes[i + 2]!;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out +=
      B64URL_ALPHABET[(n >>> 18) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 12) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 6) & 0x3f]! +
      B64URL_ALPHABET[n & 0x3f]!;
    i += 3;
  }

  const rem = len - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += B64URL_ALPHABET[(n >>> 18) & 0x3f]! + B64URL_ALPHABET[(n >>> 12) & 0x3f]!;
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      B64URL_ALPHABET[(n >>> 18) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 12) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 6) & 0x3f]!;
  }

  return out;
}

export function base64UrlEncodeString(value: string): string {
  return base64UrlEncode(textEncoder.encode(value));
}

function decodeCharValue(code: number): number {
  if (code >= 65 && code <= 90) return code - 65; // A-Z
  if (code >= 97 && code <= 122) return code - 97 + 26; // a-z
  if (code >= 48 && code <= 57) return code - 48 + 52; // 0-9
  if (code === 45) return 62; // '-'
  if (code === 95) return 63; // '_'
  throw new WolinAuthError('Invalid character in Base64URL segment');
}

/**
 * Strict canonical unpadded RFC 7515 §2 Base64URL decoder.
 * Rejects `=` padding, `+`/`/`, `len % 4 === 1`, and non-zero trailing pad bits.
 */
export function base64UrlDecode(input: string): Uint8Array {
  if (input.includes('=') || input.length % 4 === 1) {
    throw new WolinAuthError('Invalid or non-canonical Base64URL segment');
  }

  const byteLen = Math.floor((input.length * 3) / 4);
  const out = new Uint8Array(byteLen);
  let i = 0;
  let offset = 0;

  while (i + 4 <= input.length) {
    const a = decodeCharValue(input.charCodeAt(i));
    const b = decodeCharValue(input.charCodeAt(i + 1));
    const c = decodeCharValue(input.charCodeAt(i + 2));
    const d = decodeCharValue(input.charCodeAt(i + 3));
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    out[offset++] = (n >>> 16) & 0xff;
    out[offset++] = (n >>> 8) & 0xff;
    out[offset++] = n & 0xff;
    i += 4;
  }

  const rem = input.length - i;
  if (rem === 2) {
    const a = decodeCharValue(input.charCodeAt(i));
    const b = decodeCharValue(input.charCodeAt(i + 1));
    if ((b & 0x0f) !== 0) {
      throw new WolinAuthError('Non-canonical trailing bits in Base64URL segment');
    }
    const n = (a << 18) | (b << 12);
    out[offset++] = (n >>> 16) & 0xff;
  } else if (rem === 3) {
    const a = decodeCharValue(input.charCodeAt(i));
    const b = decodeCharValue(input.charCodeAt(i + 1));
    const c = decodeCharValue(input.charCodeAt(i + 2));
    if ((c & 0x03) !== 0) {
      throw new WolinAuthError('Non-canonical trailing bits in Base64URL segment');
    }
    const n = (a << 18) | (b << 12) | (c << 6);
    out[offset++] = (n >>> 16) & 0xff;
    out[offset++] = (n >>> 8) & 0xff;
  }

  return out;
}

export function base64UrlDecodeString(input: string): string {
  try {
    return textDecoder.decode(base64UrlDecode(input));
  } catch (err) {
    if (err instanceof WolinAuthError) throw err;
    throw new WolinAuthError('Invalid UTF-8 sequence in Base64URL segment', { cause: err });
  }
}

export async function sha256Bytes(data: Uint8Array | string): Promise<Uint8Array> {
  const cryptoObj = getWebCrypto();
  const input = typeof data === 'string' ? textEncoder.encode(data) : data;
  const digest = await cryptoObj.subtle.digest('SHA-256', input as BufferSource);
  return new Uint8Array(digest);
}

export async function sha256Base64Url(data: Uint8Array | string): Promise<string> {
  const digest = await sha256Bytes(data);
  return base64UrlEncode(digest);
}
