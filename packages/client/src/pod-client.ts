import { type DPoPKeyPair, signDPoPProof } from './dpop.js';
import {
  WolinAuthError,
  WolinError,
  WolinHttpError,
  WolinPreconditionError,
} from './errors.js';
import { normalizeAuthTokenType } from './oidc.js';
import {
  LDP_BASIC_CONTAINER_IRI,
  LDP_CONTAINER_IRI,
  LDP_CONTAINS_IRI,
  parseTurtle,
  RDF_TYPE_IRI,
  type RdfTriple,
} from './webid.js';

export interface WolinPodClientOptions {
  /** Base Solid Pod URL (e.g. `https://alice.wolin.id/`) for resolving relative paths. */
  podUrl?: string;
  /** Optional authenticated WebID of the active principal. */
  webId?: string;
  /** OAuth 2.0 / Solid-OIDC access token. */
  accessToken?: string;
  /** ES256 DPoP keypair bound to `accessToken` (`cnf.jkt`). */
  dpopKeyPair?: DPoPKeyPair;
  /** Authorization scheme (`'DPoP'` by default when `dpopKeyPair` is provided, otherwise `'Bearer'`). */
  tokenType?: 'DPoP' | 'Bearer' | string;
  /** Initial server-issued `DPoP-Nonce` if known. */
  dpopNonce?: string;
  /**
   * Allow transmitting `Authorization` credentials to origins different from `podUrl`
   * when `podUrl` is configured (default: `false` to prevent cross-origin token exfiltration).
   */
  allowCrossOriginAuth?: boolean;
  /** Custom `fetch` implementation for testing, SSR, or custom runtimes. */
  fetchFn?: typeof fetch;
}

export interface GetResourceOptions {
  accept?: string;
  ifNoneMatch?: string;
  ifMatch?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface PodResource {
  url: string;
  /** Final target URL when an HTTP `301`/`302`/`303`/`307`/`308` redirect (such as a signed R2/CDN asset offload) was followed. */
  redirectedUrl?: string;
  status: number;
  notModified: boolean;
  etag: string | null;
  contentType: string | null;
  linkTypes: string[];
  headers: Headers;
  bytes: Uint8Array;
  text(): string;
  json<T = unknown>(): T;
}

export interface PutResourceOptions {
  contentType?: string;
  ifMatch?: string;
  ifNoneMatch?: string;
  /** Convenience flag setting `If-None-Match: *` to prevent overwriting an existing resource. */
  createOnly?: boolean;
  linkTypes?: readonly string[];
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface PatchResourceOptions {
  /** Defaults to `'application/sparql-update'`. */
  contentType?: 'application/sparql-update' | 'text/n3' | string;
  ifMatch?: string;
  ifNoneMatch?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface PostResourceOptions {
  contentType?: string;
  slug?: string;
  linkTypes?: readonly string[];
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface WriteResourceResult {
  url: string;
  status: number;
  created: boolean;
  etag: string | null;
  location: string | null;
  headers: Headers;
}

export interface DeleteResourceOptions {
  ifMatch?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface DeleteResourceResult {
  url: string;
  status: number;
  headers: Headers;
}

export interface CreateContainerOptions {
  body?: string;
  ifNoneMatch?: string;
  ifMatch?: string;
  createOnly?: boolean;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface ListContainerOptions {
  ifNoneMatch?: string;
  ifMatch?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface ContainerChildItem {
  url: string;
  name: string;
  isContainer: boolean;
  types: string[];
}

export interface ContainerListing {
  url: string;
  etag: string | null;
  notModified: boolean;
  items: ContainerChildItem[];
  uris: string[];
  triples: RdfTriple[];
}

const textDecoder = new TextDecoder('utf-8');

function normalizeMediaType(headerVal: string | null): string | null {
  if (!headerVal) return null;
  const media = headerVal.split(';')[0]?.trim().toLowerCase();
  return media || null;
}

function splitLinkHeaderValues(linkHeader: string): string[] {
  const values: string[] = [];
  let current = '';
  let inAngleBrackets = false;
  let inQuotes = false;
  let escaped = false;

  for (let i = 0; i < linkHeader.length; i++) {
    const ch = linkHeader[i]!;
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (inQuotes && ch === '\\') {
      current += ch;
      escaped = true;
      continue;
    }
    if (!inAngleBrackets && ch === '"') {
      inQuotes = !inQuotes;
      current += ch;
      continue;
    }
    if (!inQuotes) {
      if (ch === '<') {
        inAngleBrackets = true;
      } else if (ch === '>') {
        inAngleBrackets = false;
      } else if (ch === ',' && !inAngleBrackets) {
        if (current.trim()) {
          values.push(current.trim());
        }
        current = '';
        continue;
      }
    }
    current += ch;
  }

  if (current.trim()) {
    values.push(current.trim());
  }
  return values;
}

export function parseLinkHeaderTypes(linkHeader: string | null): string[] {
  if (!linkHeader) return [];
  const types: string[] = [];
  const segments = splitLinkHeaderValues(linkHeader);

  for (const segment of segments) {
    const iriMatch = /^<([^>]+)>([\s\S]*)$/.exec(segment);
    if (!iriMatch?.[1]) continue;
    const paramsPart = iriMatch[2] ?? '';
    const relMatch = /;\s*rel\s*=\s*(?:"([^"]*)"|([^\s;,]+))/i.exec(paramsPart);
    const relTokens = (relMatch?.[1] ?? relMatch?.[2] ?? '')
      .trim()
      .toLowerCase()
      .split(/\s+/);
    if (relTokens.includes('type')) {
      types.push(iriMatch[1]);
    }
  }
  return types;
}

function appendLinkTypesHeader(headers: Headers, iris: readonly string[]): void {
  const formatted = iris.map((iri) => `<${iri}>; rel="type"`).join(', ');
  const existing = headers.get('Link');
  if (existing && existing.trim()) {
    headers.set('Link', `${existing}, ${formatted}`);
  } else {
    headers.set('Link', formatted);
  }
}

function validateSafeHttpUrl(parsed: URL, label: string): URL {
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new WolinError(
      'INVALID_ARGUMENT',
      `${label} requires http or https scheme (got '${parsed.protocol}')`,
    );
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new WolinError('INVALID_ARGUMENT', `Userinfo credentials are forbidden in ${label}`);
  }
  if (!parsed.hostname) {
    throw new WolinError('INVALID_ARGUMENT', `Missing hostname in ${label}`);
  }
  return parsed;
}

function ensureTrailingSlash(urlStr: string): string {
  const parsed = validateSafeHttpUrl(new URL(urlStr), 'Pod container URL');
  if (!parsed.pathname.endsWith('/')) {
    parsed.pathname = `${parsed.pathname}/`;
  }
  return parsed.toString();
}

function isReplayableBody(body: BodyInit | null | undefined): boolean {
  if (body === null || body === undefined) return true;
  if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream) {
    return false;
  }
  return true;
}

const MAX_REDIRECT_HOPS = 5;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const SENSITIVE_REDIRECT_HEADERS = [
  'authorization',
  'dpop',
  'cookie',
  'proxy-authorization',
] as const;

function isRedirectStatus(status: number): boolean {
  return REDIRECT_STATUS_CODES.has(status);
}

/**
 * Detect short-lived HMAC / cloud object-storage presigned URLs (e.g. Wolin Edge `/assets/...?exp=...&sig=...`,
 * Cloudflare R2 / S3 `X-Amz-Signature`, GCS `X-Goog-Signature`, or Azure SAS) that must never receive
 * `Authorization` or `DPoP` headers.
 */
function isPresignedAssetUrl(parsed: URL): boolean {
  const params = parsed.searchParams;
  if (params.has('sig') && (params.has('exp') || params.has('se') || params.has('sv'))) {
    return true;
  }
  for (const key of params.keys()) {
    const lower = key.toLowerCase();
    if (
      lower === 'x-amz-signature' ||
      lower === 'x-amz-credential' ||
      lower === 'x-goog-signature' ||
      lower === 'x-goog-credential'
    ) {
      return true;
    }
  }
  return false;
}

function stripSensitiveRedirectHeaders(headers: Headers): void {
  for (const name of SENSITIVE_REDIRECT_HEADERS) {
    headers.delete(name);
  }
}

function validateRedirectTargetUrl(rawLocation: string, previousUrl: URL): URL {
  const trimmed = rawLocation.trim();
  if (!trimmed || /[\x00-\x1f\x7f\\]/.test(trimmed)) {
    throw new WolinAuthError('Malformed or unsafe HTTP redirect Location header');
  }
  let nextUrl: URL;
  try {
    nextUrl = new URL(trimmed, previousUrl);
  } catch (err) {
    throw new WolinAuthError(`Malformed HTTP redirect Location '${rawLocation}'`, { cause: err });
  }
  if (nextUrl.protocol !== 'https:' && nextUrl.protocol !== 'http:') {
    throw new WolinAuthError(
      `Disallowed redirect scheme '${nextUrl.protocol}' while fetching Pod resource`,
    );
  }
  if (nextUrl.username !== '' || nextUrl.password !== '') {
    throw new WolinAuthError('Userinfo credentials are forbidden in redirected Pod resource URLs');
  }
  if (!nextUrl.hostname) {
    throw new WolinAuthError('Missing hostname in redirected Pod resource URL');
  }
  if (previousUrl.protocol === 'https:' && nextUrl.protocol !== 'https:') {
    throw new WolinAuthError(
      'HTTPS Pod resource request must not downgrade to cleartext HTTP via redirect',
    );
  }
  return nextUrl;
}

function validateFinalResponseUrl(response: Response, sourceUrl: URL): void {
  if (!response.url) return;
  let finalUrl: URL;
  try {
    finalUrl = new URL(response.url);
  } catch (err) {
    throw new WolinAuthError(`Malformed final response URL '${response.url}'`, { cause: err });
  }
  if (finalUrl.protocol !== 'https:' && finalUrl.protocol !== 'http:') {
    throw new WolinAuthError(`Disallowed final response scheme '${finalUrl.protocol}'`);
  }
  if (finalUrl.username !== '' || finalUrl.password !== '') {
    throw new WolinAuthError('Userinfo credentials are forbidden in final response URL');
  }
  if (sourceUrl.protocol === 'https:' && finalUrl.protocol !== 'https:') {
    throw new WolinAuthError(
      'HTTPS Pod resource request must not downgrade to cleartext HTTP via redirect',
    );
  }
}

interface InternalFetchResult {
  response: Response;
  redirectedUrl?: string;
  initialLinkHeader: string | null;
  initialEtag: string | null;
}

/**
 * Wolin (月印千江) W3C Solid 0.11 LDP Pod client with native RFC 9449 ES256 DPoP signing,
 * ETag concurrency control, and credential-safe `302` signed asset redirect handling.
 */
export class WolinPodClient {
  public readonly podUrl?: string;
  public readonly webId?: string;
  private readonly podBaseUrl?: URL;
  private readonly accessToken?: string;
  private readonly dpopKeyPair?: DPoPKeyPair;
  private readonly tokenType: 'DPoP' | 'Bearer';
  private readonly allowCrossOriginAuth: boolean;
  private readonly fetchImpl: typeof fetch;
  private dpopNonce?: string;

  constructor(options: WolinPodClientOptions = {}) {
    if (options.podUrl) {
      const normalizedPod = ensureTrailingSlash(options.podUrl.trim());
      this.podUrl = normalizedPod;
      this.podBaseUrl = new URL(normalizedPod);
    }
    this.webId = options.webId;
    this.accessToken = options.accessToken;
    this.dpopKeyPair = options.dpopKeyPair;
    this.tokenType = options.tokenType
      ? normalizeAuthTokenType(options.tokenType)
      : options.dpopKeyPair
        ? 'DPoP'
        : 'Bearer';
    this.allowCrossOriginAuth = options.allowCrossOriginAuth ?? false;
    this.dpopNonce = options.dpopNonce;
    const customFetch = options.fetchFn;
    this.fetchImpl = customFetch
      ? (input, init) => customFetch(input, init)
      : (input, init) => globalThis.fetch(input, init);
  }

  public resolveUrl(target: string | URL): string {
    if (target instanceof URL) {
      return validateSafeHttpUrl(new URL(target.toString()), 'Resource URL').toString();
    }

    const trimmed = target.trim();
    if (!trimmed || /[\s\x00-\x1f\x7f\\]/.test(trimmed)) {
      throw new WolinError(
        'INVALID_ARGUMENT',
        'Resource URL or path is empty or contains invalid characters',
      );
    }

    if (trimmed.startsWith('//')) {
      throw new WolinError(
        'INVALID_ARGUMENT',
        `Protocol-relative resource path '${trimmed}' is forbidden`,
      );
    }

    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
      return validateSafeHttpUrl(new URL(trimmed), 'Resource URL').toString();
    }

    if (!this.podUrl || !this.podBaseUrl) {
      throw new WolinError(
        'INVALID_ARGUMENT',
        `Relative resource path '${trimmed}' requires 'podUrl' to be configured on WolinPodClient`,
      );
    }

    // Disallow `.` / `..` path traversal or percent-encoded slashes/backslashes in relative Pod paths
    const rawPathPart = trimmed.split(/[?#]/)[0] ?? '';
    const segments = rawPathPart.split('/');
    for (const seg of segments) {
      let decodedSeg: string;
      try {
        decodedSeg = decodeURIComponent(seg);
      } catch (err) {
        throw new WolinError(
          'INVALID_ARGUMENT',
          `Malformed percent-encoding in Pod resource path '${trimmed}'`,
          { cause: err },
        );
      }
      if (
        decodedSeg === '..' ||
        decodedSeg === '.' ||
        decodedSeg.includes('/') ||
        decodedSeg.includes('\\')
      ) {
        throw new WolinError(
          'INVALID_ARGUMENT',
          `Path traversal or encoded separator ('${seg}') is forbidden in Pod resource path '${trimmed}'`,
        );
      }
    }

    const relPath = `./${trimmed.startsWith('/') ? trimmed.slice(1) : trimmed}`;
    const resolved = validateSafeHttpUrl(new URL(relPath, this.podUrl), 'Pod resource URL');

    if (
      resolved.origin !== this.podBaseUrl.origin ||
      !resolved.pathname.startsWith(this.podBaseUrl.pathname)
    ) {
      throw new WolinError(
        'INVALID_ARGUMENT',
        `Resolved URL '${resolved.toString()}' escapes configured Pod root '${this.podUrl}'`,
      );
    }

    return resolved.toString();
  }

  private async attachAuthHeaders(
    headers: Headers,
    method: string,
    targetUrl: string,
    nonce?: string,
  ): Promise<void> {
    if (this.accessToken) {
      if (this.tokenType === 'DPoP') {
        if (!this.dpopKeyPair) {
          throw new WolinAuthError(
            "Token type 'DPoP' requires 'dpopKeyPair' to be configured on WolinPodClient",
          );
        }
        const proof = await signDPoPProof({
          keyPair: this.dpopKeyPair,
          htm: method,
          htu: targetUrl,
          accessToken: this.accessToken,
          nonce,
        });
        headers.set('Authorization', `DPoP ${this.accessToken}`);
        headers.set('DPoP', proof);
      } else {
        headers.set('Authorization', `Bearer ${this.accessToken}`);
      }
    } else if (this.dpopKeyPair) {
      const proof = await signDPoPProof({
        keyPair: this.dpopKeyPair,
        htm: method,
        htu: targetUrl,
        nonce,
      });
      headers.set('DPoP', proof);
    }
  }

  private async fetchInternal(
    input: string | URL,
    init: RequestInit = {},
  ): Promise<InternalFetchResult> {
    const resolvedUrl = this.resolveUrl(input);
    const initialParsed = new URL(resolvedUrl);
    const method = (init.method ?? 'GET').toUpperCase();

    if (this.accessToken && this.podBaseUrl && !this.allowCrossOriginAuth) {
      if (initialParsed.origin !== this.podBaseUrl.origin) {
        throw new WolinAuthError(
          `Blocked cross-origin credential transmission from Pod origin '${this.podBaseUrl.origin}' to '${initialParsed.origin}'`,
        );
      }
    }

    const requestedRedirect: RequestRedirect = init.redirect ?? 'follow';
    const canSafelyFollowRedirects =
      requestedRedirect === 'follow' && (method === 'GET' || method === 'HEAD');
    const callerHeaders = new Headers(init.headers);
    const hasSensitiveAuth = Boolean(
      this.accessToken ||
        this.dpopKeyPair ||
        callerHeaders.has('authorization') ||
        callerHeaders.has('dpop') ||
        callerHeaders.has('cookie') ||
        callerHeaders.has('proxy-authorization'),
    );

    const firstHopRedirectMode: RequestRedirect =
      canSafelyFollowRedirects && hasSensitiveAuth ? 'manual' : requestedRedirect;

    const executeAttempt = async (
      nonce?: string,
      overrideRedirect?: RequestRedirect,
    ): Promise<Response> => {
      const headers = new Headers(init.headers);
      await this.attachAuthHeaders(headers, method, resolvedUrl, nonce);
      return this.fetchImpl(resolvedUrl, {
        ...init,
        method,
        headers,
        redirect: overrideRedirect ?? firstHopRedirectMode,
      });
    };

    let response = await executeAttempt(this.dpopNonce);
    const nextNonce = response.headers.get('DPoP-Nonce');
    if (nextNonce) {
      this.dpopNonce = nextNonce;
    }

    // RFC 9449 §9 Resource Server DPoP-Nonce challenge single retry
    if (
      response.status === 401 &&
      nextNonce &&
      this.dpopKeyPair &&
      isReplayableBody(init.body) &&
      (response.headers.get('WWW-Authenticate') ?? '').includes('use_dpop_nonce')
    ) {
      response = await executeAttempt(nextNonce);
      const refreshedNonce = response.headers.get('DPoP-Nonce');
      if (refreshedNonce) {
        this.dpopNonce = refreshedNonce;
      }
    }

    if (!canSafelyFollowRedirects) {
      return {
        response,
        initialLinkHeader: null,
        initialEtag: null,
      };
    }

    // Browser WHATWG Fetch filters manual 3xx responses to `opaqueredirect` (status 0, hidden Location).
    // Retry once with `redirect: 'follow'` and enforce HTTPS non-downgrade on `response.url`.
    if (response.type === 'opaqueredirect') {
      response = await executeAttempt(this.dpopNonce, 'follow');
      const followNonce = response.headers.get('DPoP-Nonce');
      if (followNonce) {
        this.dpopNonce = followNonce;
      }
      validateFinalResponseUrl(response, initialParsed);
      return {
        response,
        redirectedUrl:
          response.url && response.url !== resolvedUrl ? response.url : undefined,
        initialLinkHeader: null,
        initialEtag: null,
      };
    }

    const initialLinkHeader = isRedirectStatus(response.status)
      ? response.headers.get('Link')
      : null;
    const initialEtag = isRedirectStatus(response.status)
      ? response.headers.get('ETag')
      : null;

    let currentUrl = initialParsed;
    let currentMethod = method;
    let hops = 0;

    while (isRedirectStatus(response.status)) {
      const location = response.headers.get('Location');
      if (!location) {
        break;
      }
      if (hops >= MAX_REDIRECT_HOPS) {
        await response.body?.cancel().catch(() => undefined);
        throw new WolinHttpError({
          status: response.status,
          statusText: 'Too Many Redirects',
          url: currentUrl.toString(),
          method: currentMethod,
          message: `Exceeded maximum redirect hops (${MAX_REDIRECT_HOPS}) while fetching '${resolvedUrl}'`,
        });
      }

      await response.body?.cancel().catch(() => undefined);
      const nextUrl = validateRedirectTargetUrl(location, currentUrl);
      if (response.status === 303 && currentMethod !== 'HEAD') {
        currentMethod = 'GET';
      }

      const isWithinPodScope =
        this.podBaseUrl !== undefined
          ? nextUrl.origin === this.podBaseUrl.origin &&
            nextUrl.pathname.startsWith(this.podBaseUrl.pathname)
          : nextUrl.origin === initialParsed.origin;

      const stripCredentials = !isWithinPodScope || isPresignedAssetUrl(nextUrl);

      const hopHeaders = new Headers(init.headers);
      stripSensitiveRedirectHeaders(hopHeaders);
      if (!stripCredentials) {
        await this.attachAuthHeaders(hopHeaders, currentMethod, nextUrl.toString(), this.dpopNonce);
      }

      const hopInit: RequestInit = {
        ...init,
        method: currentMethod,
        headers: hopHeaders,
        body: undefined,
        redirect: 'manual',
      };

      response = await this.fetchImpl(nextUrl.toString(), hopInit);
      if (!stripCredentials) {
        const hopNonce = response.headers.get('DPoP-Nonce');
        if (hopNonce) {
          this.dpopNonce = hopNonce;
        }
      }

      // If a stripped presigned/CDN hop itself redirects inside a browser (`opaqueredirect`),
      // `hopHeaders` already has zero credentials, so native `redirect: 'follow'` is completely safe.
      if (response.type === 'opaqueredirect' && stripCredentials) {
        response = await this.fetchImpl(nextUrl.toString(), {
          ...hopInit,
          redirect: 'follow',
        });
      }

      currentUrl = nextUrl;
      hops += 1;
    }

    validateFinalResponseUrl(response, currentUrl);
    const redirectedUrl =
      hops > 0
        ? currentUrl.toString()
        : response.url && response.url !== resolvedUrl
          ? response.url
          : undefined;

    return {
      response,
      redirectedUrl,
      initialLinkHeader,
      initialEtag,
    };
  }

  /**
   * Perform an HTTP request against a Solid Pod, signing a fresh RFC 9449 DPoP proof
   * (`htm`, `htu`, `iat`, `jti`, `ath`) when configured with `accessToken` + `dpopKeyPair`,
   * and stripping `Authorization` / `DPoP` headers across `302` signed asset redirects.
   */
  public async fetchWithDPoP(input: string | URL, init: RequestInit = {}): Promise<Response> {
    const { response } = await this.fetchInternal(input, init);
    return response;
  }

  /**
   * Read an RDF or binary Non-RDF resource from the Pod (`GET`) with ETag (`If-None-Match` / `If-Match`)
   * and credential-safe `302` signed R2/CDN asset redirect support.
   */
  public async getResource(
    url: string | URL,
    options: GetResourceOptions = {},
  ): Promise<PodResource> {
    const resolvedUrl = this.resolveUrl(url);
    const headers = new Headers(options.headers);
    if (options.accept && !headers.has('Accept')) {
      headers.set('Accept', options.accept);
    }
    if (options.ifNoneMatch) {
      headers.set('If-None-Match', options.ifNoneMatch);
    }
    if (options.ifMatch) {
      headers.set('If-Match', options.ifMatch);
    }

    const { response, redirectedUrl, initialLinkHeader, initialEtag } = await this.fetchInternal(
      resolvedUrl,
      {
        method: 'GET',
        headers,
        signal: options.signal,
      },
    );

    const effectiveEtag = response.headers.get('ETag') ?? initialEtag;
    const responseLinkTypes = parseLinkHeaderTypes(response.headers.get('Link'));
    const effectiveLinkTypes =
      responseLinkTypes.length > 0 ? responseLinkTypes : parseLinkHeaderTypes(initialLinkHeader);

    if (response.status === 304) {
      const empty = new Uint8Array(0);
      return {
        url: resolvedUrl,
        ...(redirectedUrl ? { redirectedUrl } : {}),
        status: 304,
        notModified: true,
        etag: effectiveEtag,
        contentType: normalizeMediaType(response.headers.get('Content-Type')),
        linkTypes: effectiveLinkTypes,
        headers: response.headers,
        bytes: empty,
        text: () => '',
        json: <T = unknown>(): T => {
          throw new WolinError(
            'INVALID_ARGUMENT',
            'Cannot parse JSON body from a 304 Not Modified response',
          );
        },
      };
    }

    if (!response.ok) {
      await this.throwHttpError(response, 'GET', resolvedUrl);
    }

    const arrayBuf = await response.arrayBuffer();
    const bytes = new Uint8Array(arrayBuf);

    return {
      url: resolvedUrl,
      ...(redirectedUrl ? { redirectedUrl } : {}),
      status: response.status,
      notModified: false,
      etag: effectiveEtag,
      contentType: normalizeMediaType(response.headers.get('Content-Type')),
      linkTypes: effectiveLinkTypes,
      headers: response.headers,
      bytes,
      text: () => textDecoder.decode(bytes),
      json: <T = unknown>(): T => JSON.parse(textDecoder.decode(bytes)) as T,
    };
  }

  /**
   * Convenience alias for {@link getResource} (`GET` RDF or binary/blob resource with safe `302` redirect handling).
   */
  public async get(url: string | URL, options: GetResourceOptions = {}): Promise<PodResource> {
    return this.getResource(url, options);
  }

  /**
   * Read a binary/blob `NonRDFSource` resource (such as `.glb`, `.vrm`, image, or media) as a standard `Blob`,
   * following `302` signed R2/CDN redirects without leaking `Authorization` or `DPoP` headers.
   */
  public async getBlob(url: string | URL, options: GetResourceOptions = {}): Promise<Blob> {
    const res = await this.getResource(url, options);
    if (res.notModified) {
      throw new WolinError(
        'INVALID_ARGUMENT',
        'Cannot construct Blob payload from a 304 Not Modified response',
      );
    }
    return new Blob([res.bytes as BlobPart], {
      type: res.contentType ?? 'application/octet-stream',
    });
  }

  /**
   * Create or replace a Solid LDP resource (`PUT`) with optimistic concurrency (`If-Match` / `If-None-Match`).
   */
  public async putResource(
    url: string | URL,
    body: string | Uint8Array | ArrayBuffer,
    options: PutResourceOptions = {},
  ): Promise<WriteResourceResult> {
    if (options.ifMatch && (options.createOnly || options.ifNoneMatch === '*')) {
      throw new WolinError(
        'INVALID_ARGUMENT',
        "Conflicting ETag preconditions: cannot combine 'ifMatch' with 'createOnly' / 'If-None-Match: *'",
      );
    }

    const resolvedUrl = this.resolveUrl(url);
    const headers = new Headers(options.headers);

    const defaultContentType =
      typeof body === 'string' ? 'text/turtle' : 'application/octet-stream';
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', options.contentType ?? defaultContentType);
    }

    if (options.ifMatch) {
      headers.set('If-Match', options.ifMatch);
    }
    if (options.createOnly) {
      headers.set('If-None-Match', '*');
    } else if (options.ifNoneMatch) {
      headers.set('If-None-Match', options.ifNoneMatch);
    }

    if (options.linkTypes && options.linkTypes.length > 0) {
      appendLinkTypesHeader(headers, options.linkTypes);
    }

    const requestBody: BodyInit =
      body instanceof Uint8Array ? (body as unknown as BodyInit) : body;

    const response = await this.fetchWithDPoP(resolvedUrl, {
      method: 'PUT',
      headers,
      body: requestBody,
      signal: options.signal,
    });

    if (!response.ok) {
      await this.throwHttpError(response, 'PUT', resolvedUrl);
    }

    return {
      url: resolvedUrl,
      status: response.status,
      created: response.status === 201,
      etag: response.headers.get('ETag'),
      location: response.headers.get('Location'),
      headers: response.headers,
    };
  }

  /**
   * Apply a SPARQL 1.1 Update (`application/sparql-update`) or N3 Patch (`PATCH`) to an RDF resource.
   */
  public async patchResource(
    url: string | URL,
    patchBody: string,
    options: PatchResourceOptions = {},
  ): Promise<WriteResourceResult> {
    const resolvedUrl = this.resolveUrl(url);
    const headers = new Headers(options.headers);
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', options.contentType ?? 'application/sparql-update');
    }
    if (options.ifMatch) {
      headers.set('If-Match', options.ifMatch);
    }
    if (options.ifNoneMatch) {
      headers.set('If-None-Match', options.ifNoneMatch);
    }

    const response = await this.fetchWithDPoP(resolvedUrl, {
      method: 'PATCH',
      headers,
      body: patchBody,
      signal: options.signal,
    });

    if (!response.ok) {
      await this.throwHttpError(response, 'PATCH', resolvedUrl);
    }

    return {
      url: resolvedUrl,
      status: response.status,
      created: response.status === 201,
      etag: response.headers.get('ETag'),
      location: response.headers.get('Location'),
      headers: response.headers,
    };
  }

  /**
   * Create a child resource inside an LDP Container via `POST` (with optional `Slug` header).
   */
  public async postResource(
    containerUrl: string | URL,
    body: string | Uint8Array | ArrayBuffer,
    options: PostResourceOptions = {},
  ): Promise<WriteResourceResult> {
    const resolvedUrl = ensureTrailingSlash(this.resolveUrl(containerUrl));
    const headers = new Headers(options.headers);

    const defaultContentType =
      typeof body === 'string' ? 'text/turtle' : 'application/octet-stream';
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', options.contentType ?? defaultContentType);
    }
    if (options.slug) {
      headers.set('Slug', options.slug);
    }
    if (options.linkTypes && options.linkTypes.length > 0) {
      appendLinkTypesHeader(headers, options.linkTypes);
    }

    const requestBody: BodyInit =
      body instanceof Uint8Array ? (body as unknown as BodyInit) : body;

    const response = await this.fetchWithDPoP(resolvedUrl, {
      method: 'POST',
      headers,
      body: requestBody,
      signal: options.signal,
    });

    if (!response.ok) {
      await this.throwHttpError(response, 'POST', resolvedUrl);
    }

    return {
      url: resolvedUrl,
      status: response.status,
      created: response.status === 201,
      etag: response.headers.get('ETag'),
      location: response.headers.get('Location'),
      headers: response.headers,
    };
  }

  /**
   * Delete a Solid LDP resource or empty container (`DELETE`), optionally guarded by `If-Match`.
   */
  public async deleteResource(
    url: string | URL,
    options: DeleteResourceOptions = {},
  ): Promise<DeleteResourceResult> {
    const resolvedUrl = this.resolveUrl(url);
    const headers = new Headers(options.headers);
    if (options.ifMatch) {
      headers.set('If-Match', options.ifMatch);
    }

    const response = await this.fetchWithDPoP(resolvedUrl, {
      method: 'DELETE',
      headers,
      signal: options.signal,
    });

    if (!response.ok) {
      await this.throwHttpError(response, 'DELETE', resolvedUrl);
    }

    return {
      url: resolvedUrl,
      status: response.status,
      headers: response.headers,
    };
  }

  /**
   * Create a W3C Solid `ldp:BasicContainer` via `PUT` (ensuring a trailing `/` and `Link: <ldp#BasicContainer>; rel="type"`).
   */
  public async createContainer(
    url: string | URL,
    options: CreateContainerOptions = {},
  ): Promise<WriteResourceResult> {
    const containerUrl = ensureTrailingSlash(this.resolveUrl(url));
    return this.putResource(containerUrl, options.body ?? '', {
      contentType: 'text/turtle',
      linkTypes: [LDP_BASIC_CONTAINER_IRI],
      ifMatch: options.ifMatch,
      ifNoneMatch: options.ifNoneMatch,
      createOnly: options.createOnly,
      headers: options.headers,
      signal: options.signal,
    });
  }

  /**
   * List direct child resources (`ldp:contains`) of a Solid LDP Container.
   */
  public async listContainer(
    url: string | URL,
    options: ListContainerOptions = {},
  ): Promise<ContainerListing> {
    const containerUrl = ensureTrailingSlash(this.resolveUrl(url));
    const resource = await this.getResource(containerUrl, {
      accept: 'text/turtle',
      ifNoneMatch: options.ifNoneMatch,
      ifMatch: options.ifMatch,
      headers: options.headers,
      signal: options.signal,
    });

    if (resource.notModified) {
      return {
        url: containerUrl,
        etag: resource.etag,
        notModified: true,
        items: [],
        uris: [],
        triples: [],
      };
    }

    const triples = parseTurtle(resource.text(), containerUrl);
    const childUris = new Set<string>();
    const typesBySubject = new Map<string, Set<string>>();

    for (const triple of triples) {
      if (
        triple.subject === containerUrl &&
        triple.predicate === LDP_CONTAINS_IRI &&
        triple.objectType === 'iri'
      ) {
        childUris.add(triple.object);
      }
      if (triple.predicate === RDF_TYPE_IRI && triple.objectType === 'iri') {
        let typeSet = typesBySubject.get(triple.subject);
        if (!typeSet) {
          typeSet = new Set<string>();
          typesBySubject.set(triple.subject, typeSet);
        }
        typeSet.add(triple.object);
      }
    }

    const sortedUris = Array.from(childUris).sort();
    const items: ContainerChildItem[] = sortedUris.map((childUrl) => {
      const types = Array.from(typesBySubject.get(childUrl) ?? []);
      const isContainer =
        childUrl.endsWith('/') ||
        types.includes(LDP_BASIC_CONTAINER_IRI) ||
        types.includes(LDP_CONTAINER_IRI);
      const name = childUrl.startsWith(containerUrl)
        ? childUrl.slice(containerUrl.length)
        : (new URL(childUrl).pathname.split('/').filter(Boolean).pop() ?? childUrl);

      return {
        url: childUrl,
        name,
        isContainer,
        types,
      };
    });

    return {
      url: containerUrl,
      etag: resource.etag,
      notModified: false,
      items,
      uris: sortedUris,
      triples,
    };
  }

  private async throwHttpError(
    response: Response,
    method: string,
    url: string,
  ): Promise<never> {
    const body = await response.text().catch(() => '');
    if (response.status === 412) {
      throw new WolinPreconditionError({
        status: response.status,
        statusText: response.statusText || 'Precondition Failed',
        url,
        method,
        body,
        headers: response.headers,
      });
    }
    throw new WolinHttpError({
      status: response.status,
      statusText: response.statusText || 'HTTP Error',
      url,
      method,
      body,
      headers: response.headers,
    });
  }
}
