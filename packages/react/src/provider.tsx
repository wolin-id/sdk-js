import {
  computeJwkThumbprint,
  createSolidAuthRequest,
  DEFAULT_WOLIN_OIDC_ISSUER,
  type DPoPKeyPair,
  type DPoPPublicJwk,
  decodeJwtPayload,
  discoverOidcProvider,
  exchangeCodeForTokens,
  fetchWebIdProfile,
  generateDPoPKeyPair,
  generateRandomState,
  normalizeAuthTokenType,
  type OidcProviderMetadata,
  type SolidAuthRequest,
  verifyWebIdOidcIssuer,
  type WebIdProfile,
  WolinAuthError,
  WolinPodClient,
} from '@wolin-id/client';
import {
  createContext,
  type ReactElement,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

export const WOLIN_PENDING_AUTH_STORAGE_KEY = 'wolin:solid-oidc:pending';
const WOLIN_DPOP_FALLBACK_STORAGE_PREFIX = 'wolin:solid-oidc:dpop-jwk:';
export const WOLIN_DPOP_IDB_NAME = 'wolin-solid-auth';
const WOLIN_DPOP_IDB_VERSION = 1;
export const WOLIN_DPOP_IDB_STORE = 'dpop-keys';
const WOLIN_DPOP_ACTIVE_IDB_KEY = 'active-dpop-keypair';

export interface WolinSessionState {
  webId: string;
  accessToken: string;
  tokenType: 'DPoP' | 'Bearer';
  dpopKeyPair?: DPoPKeyPair;
  dpopJkt?: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  podUrl?: string;
  oidcIssuer?: string;
  dpopNonce?: string;
}

export interface LoginOptions {
  /** Explicit Solid-OIDC issuer URL (e.g. `https://auth.wolin.id`). */
  oidcIssuer?: string;
  /** User WebID URI from which `solid:oidcIssuer` can be discovered automatically. */
  webId?: string;
  clientId?: string;
  redirectUri?: string;
  scopes?: readonly string[];
  state?: string;
  nonce?: string;
  prompt?: string;
  /** Whether to navigate `window.location` automatically in browser environments (default: `true`). */
  redirect?: boolean;
}

export interface LoginStartResult {
  authRequest: SolidAuthRequest;
  dpopKeyPair: DPoPKeyPair;
  providerMetadata: OidcProviderMetadata;
}

export interface PendingSolidAuth {
  codeVerifier: string;
  expectedState: string;
  tokenEndpoint: string;
  oidcIssuer: string;
  clientId?: string;
  redirectUri?: string;
  nonce?: string;
  dpopKeyPair: DPoPKeyPair;
}

export interface StoredPendingSolidAuth {
  state: string;
  codeVerifier: string;
  nonce: string;
  redirectUri: string;
  issuer: string;
  clientId: string;
  tokenEndpoint?: string;
  dpopJkt: string;
  createdAt?: number;
}

export interface WolinContextValue {
  session: WolinSessionState | null;
  profile: WebIdProfile | null;
  isAuthenticated: boolean;
  isAuthenticating: boolean;
  error: Error | null;
  client: WolinPodClient;
  login: (options?: LoginOptions) => Promise<LoginStartResult>;
  handleRedirectCallback: (
    callbackUrl: string,
    overridePending?: PendingSolidAuth,
  ) => Promise<WolinSessionState>;
  setSession: (session: WolinSessionState | null) => void;
  logout: () => void;
  refreshProfile: () => Promise<WebIdProfile | null>;
}

export interface WolinProviderProps {
  children: ReactNode;
  initialSession?: WolinSessionState | null;
  clientId?: string;
  redirectUri?: string;
  /** Fallback Solid-OIDC issuer URL when not discovered via WebID (defaults to `https://auth.wolin.id`). */
  defaultOidcIssuer?: string;
  podUrl?: string;
  fetchFn?: typeof fetch;
  onSessionChange?: (session: WolinSessionState | null) => void;
}

export const WolinContext = createContext<WolinContextValue | null>(null);

const memoryFallbackStorage = new Map<string, string>();

function getSafeSessionStorage(): Storage | null {
  try {
    if (typeof globalThis !== 'undefined' && 'sessionStorage' in globalThis && globalThis.sessionStorage) {
      return globalThis.sessionStorage;
    }
  } catch {
    // Blocked in sandboxed iframe or SSR
  }
  return null;
}

function writeStorageItem(key: string, value: string): void {
  const store = getSafeSessionStorage();
  if (store) {
    store.setItem(key, value);
  } else {
    memoryFallbackStorage.set(key, value);
  }
}

function readStorageItem(key: string): string | null {
  const store = getSafeSessionStorage();
  if (store) {
    return store.getItem(key);
  }
  return memoryFallbackStorage.get(key) ?? null;
}

function removeStorageItem(key: string): void {
  const store = getSafeSessionStorage();
  if (store) {
    store.removeItem(key);
  }
  memoryFallbackStorage.delete(key);
}

function clearFallbackDpopStorage(): void {
  const store = getSafeSessionStorage();
  if (store) {
    const keysToRemove: string[] = [];
    for (let i = 0; i < store.length; i++) {
      const k = store.key(i);
      if (k && k.startsWith(WOLIN_DPOP_FALLBACK_STORAGE_PREFIX)) {
        keysToRemove.push(k);
      }
    }
    for (const k of keysToRemove) {
      store.removeItem(k);
    }
  }
  for (const k of Array.from(memoryFallbackStorage.keys())) {
    if (k.startsWith(WOLIN_DPOP_FALLBACK_STORAGE_PREFIX)) {
      memoryFallbackStorage.delete(k);
    }
  }
}

function openDpopIndexedDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof globalThis === 'undefined' || !globalThis.indexedDB) {
      reject(new Error('IndexedDB is not available in this environment'));
      return;
    }
    let req: IDBOpenDBRequest;
    try {
      req = globalThis.indexedDB.open(WOLIN_DPOP_IDB_NAME, WOLIN_DPOP_IDB_VERSION);
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(WOLIN_DPOP_IDB_STORE)) {
        db.createObjectStore(WOLIN_DPOP_IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('Failed to open Wolin DPoP IndexedDB'));
  });
}

function isValidDpopKeyPairRecord(candidate: unknown, expectedJkt?: string): candidate is DPoPKeyPair {
  if (!candidate || typeof candidate !== 'object') return false;
  const rec = candidate as Partial<DPoPKeyPair>;
  if (!rec.privateKey || !rec.publicKey || !rec.publicJwk || typeof rec.jkt !== 'string') {
    return false;
  }
  if (expectedJkt && rec.jkt !== expectedJkt) {
    return false;
  }
  return true;
}

/**
 * Persist a Web Crypto ES256 `DPoPKeyPair` (with non-extractable `privateKey`) in IndexedDB.
 */
export async function saveDpopKeyPairToIndexedDb(
  keyPair: DPoPKeyPair,
  markActive = false,
): Promise<void> {
  const db = await openDpopIndexedDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(WOLIN_DPOP_IDB_STORE, 'readwrite');
    const store = tx.objectStore(WOLIN_DPOP_IDB_STORE);
    store.put(keyPair, `jkt:${keyPair.jkt}`);
    if (markActive) {
      store.put(keyPair, WOLIN_DPOP_ACTIVE_IDB_KEY);
    }
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error('Failed to persist DPoP keypair in IndexedDB'));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error('IndexedDB transaction aborted while saving DPoP keypair'));
    };
  });
}

/**
 * Restore a `DPoPKeyPair` from IndexedDB by RFC 7638 `jkt` thumbprint (or active keypair).
 */
export async function loadDpopKeyPairFromIndexedDb(jkt?: string): Promise<DPoPKeyPair | null> {
  let db: IDBDatabase;
  try {
    db = await openDpopIndexedDb();
  } catch {
    return null;
  }
  const lookupKey = jkt ? `jkt:${jkt}` : WOLIN_DPOP_ACTIVE_IDB_KEY;
  return new Promise<DPoPKeyPair | null>((resolve) => {
    try {
      const tx = db.transaction(WOLIN_DPOP_IDB_STORE, 'readonly');
      const req = tx.objectStore(WOLIN_DPOP_IDB_STORE).get(lookupKey);
      req.onsuccess = () => {
        db.close();
        const val = req.result as unknown;
        resolve(isValidDpopKeyPairRecord(val, jkt) ? val : null);
      };
      req.onerror = () => {
        db.close();
        resolve(null);
      };
    } catch {
      db.close();
      resolve(null);
    }
  });
}

/**
 * Clear persisted DPoP keypairs from IndexedDB (called on logout / session reset).
 */
export async function clearDpopKeyPairsFromIndexedDb(): Promise<void> {
  let db: IDBDatabase;
  try {
    db = await openDpopIndexedDb();
  } catch {
    return;
  }
  await new Promise<void>((resolve) => {
    try {
      const tx = db.transaction(WOLIN_DPOP_IDB_STORE, 'readwrite');
      tx.objectStore(WOLIN_DPOP_IDB_STORE).clear();
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        resolve();
      };
    } catch {
      db.close();
      resolve();
    }
  });
}

async function deleteDpopKeyPairByJkt(jkt: string): Promise<void> {
  removeStorageItem(`${WOLIN_DPOP_FALLBACK_STORAGE_PREFIX}${jkt}`);
  let db: IDBDatabase;
  try {
    db = await openDpopIndexedDb();
  } catch {
    return;
  }
  await new Promise<void>((resolve) => {
    try {
      const tx = db.transaction(WOLIN_DPOP_IDB_STORE, 'readwrite');
      tx.objectStore(WOLIN_DPOP_IDB_STORE).delete(`jkt:${jkt}`);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        resolve();
      };
    } catch {
      db.close();
      resolve();
    }
  });
}

async function createAndPersistPendingDpopKeyPair(): Promise<DPoPKeyPair> {
  if (typeof globalThis !== 'undefined' && globalThis.indexedDB) {
    try {
      const nonExtractableKeyPair = await generateDPoPKeyPair({ extractable: false });
      await saveDpopKeyPairToIndexedDb(nonExtractableKeyPair, false);
      return nonExtractableKeyPair;
    } catch {
      // Fall through to JWK restoration fallback when IndexedDB is blocked (e.g. strict sandbox)
    }
  }

  // Fallback for non-IDB environments (e.g. jsdom / restricted WebViews):
  // Export JWK once for redirect persistence, then re-import privateKey as non-extractable.
  const tempExtractable = await generateDPoPKeyPair({ extractable: true });
  const exportedPrivateJwk = await globalThis.crypto.subtle.exportKey(
    'jwk',
    tempExtractable.privateKey,
  );
  writeStorageItem(
    `${WOLIN_DPOP_FALLBACK_STORAGE_PREFIX}${tempExtractable.jkt}`,
    JSON.stringify({
      privateJwk: exportedPrivateJwk,
      publicJwk: tempExtractable.publicJwk,
      jkt: tempExtractable.jkt,
    }),
  );

  const nonExtractablePrivate = await globalThis.crypto.subtle.importKey(
    'jwk',
    exportedPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );

  return {
    privateKey: nonExtractablePrivate,
    publicKey: tempExtractable.publicKey,
    publicJwk: tempExtractable.publicJwk,
    jkt: tempExtractable.jkt,
  };
}

async function restorePendingDpopKeyPair(expectedJkt: string): Promise<DPoPKeyPair> {
  const fromIdb = await loadDpopKeyPairFromIndexedDb(expectedJkt);
  if (fromIdb) {
    try {
      await saveDpopKeyPairToIndexedDb(fromIdb, true);
    } catch {
      // Ignore secondary active-slot write failure
    }
    return fromIdb;
  }

  const fallbackKey = `${WOLIN_DPOP_FALLBACK_STORAGE_PREFIX}${expectedJkt}`;
  const rawFallback = readStorageItem(fallbackKey);
  if (rawFallback) {
    removeStorageItem(fallbackKey);
    let parsed: { privateJwk?: JsonWebKey; publicJwk?: DPoPPublicJwk; jkt?: string };
    try {
      parsed = JSON.parse(rawFallback) as {
        privateJwk?: JsonWebKey;
        publicJwk?: DPoPPublicJwk;
        jkt?: string;
      };
    } catch (err) {
      throw new WolinAuthError('Corrupted DPoP fallback key material in storage', { cause: err });
    }
    if (!parsed.privateJwk || !parsed.publicJwk) {
      throw new WolinAuthError('Incomplete DPoP fallback key material in storage');
    }
    const computedJkt = await computeJwkThumbprint(parsed.publicJwk);
    if (computedJkt !== expectedJkt) {
      throw new WolinAuthError('Restored DPoP keypair thumbprint does not match expected dpop_jkt');
    }
    const [privateKey, publicKey] = await Promise.all([
      globalThis.crypto.subtle.importKey(
        'jwk',
        parsed.privateJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign'],
      ),
      globalThis.crypto.subtle.importKey(
        'jwk',
        parsed.publicJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      ),
    ]);
    return {
      privateKey,
      publicKey,
      publicJwk: parsed.publicJwk,
      jkt: computedJkt,
    };
  }

  throw new WolinAuthError(
    `Failed to restore DPoP keypair matching pending Solid-OIDC authorization (dpop_jkt '${expectedJkt}')`,
  );
}

function savePendingAuthState(pending: StoredPendingSolidAuth): void {
  writeStorageItem(WOLIN_PENDING_AUTH_STORAGE_KEY, JSON.stringify(pending));
}

function consumePendingAuthState(): StoredPendingSolidAuth | null {
  const raw = readStorageItem(WOLIN_PENDING_AUTH_STORAGE_KEY);
  if (!raw) return null;
  removeStorageItem(WOLIN_PENDING_AUTH_STORAGE_KEY);

  let parsed: Record<string, unknown>;
  try {
    const json = JSON.parse(raw) as unknown;
    if (!json || typeof json !== 'object' || Array.isArray(json)) {
      throw new WolinAuthError('Stored pending Solid-OIDC state must be a JSON object');
    }
    parsed = json as Record<string, unknown>;
  } catch (err) {
    if (err instanceof WolinAuthError) throw err;
    throw new WolinAuthError('Malformed JSON in stored pending Solid-OIDC state', { cause: err });
  }

  const state =
    typeof parsed.state === 'string'
      ? parsed.state
      : typeof parsed.expectedState === 'string'
        ? parsed.expectedState
        : '';
  const issuer =
    typeof parsed.issuer === 'string'
      ? parsed.issuer
      : typeof parsed.oidcIssuer === 'string'
        ? parsed.oidcIssuer
        : '';
  const codeVerifier = typeof parsed.codeVerifier === 'string' ? parsed.codeVerifier : '';
  const nonce = typeof parsed.nonce === 'string' ? parsed.nonce : '';
  const redirectUri = typeof parsed.redirectUri === 'string' ? parsed.redirectUri : '';
  const clientId = typeof parsed.clientId === 'string' ? parsed.clientId : '';
  const tokenEndpoint =
    typeof parsed.tokenEndpoint === 'string' && parsed.tokenEndpoint.trim()
      ? parsed.tokenEndpoint.trim()
      : undefined;
  const dpopJkt = typeof parsed.dpopJkt === 'string' ? parsed.dpopJkt : '';
  const createdAt = typeof parsed.createdAt === 'number' ? parsed.createdAt : undefined;

  return {
    state,
    codeVerifier,
    nonce,
    redirectUri,
    issuer,
    clientId,
    tokenEndpoint,
    dpopJkt,
    createdAt,
  };
}

function clearAllPersistedAuthArtifacts(): void {
  removeStorageItem(WOLIN_PENDING_AUTH_STORAGE_KEY);
  clearFallbackDpopStorage();
  void clearDpopKeyPairsFromIndexedDb();
}

function extractIssuerFromTokens(idToken?: string, accessToken?: string): string | undefined {
  for (const tok of [idToken, accessToken]) {
    if (!tok || tok.split('.').length !== 3) continue;
    try {
      const claims = decodeJwtPayload(tok);
      if (typeof claims.iss === 'string' && claims.iss.trim()) {
        return claims.iss.trim();
      }
    } catch {
      // Ignore opaque access token
    }
  }
  return undefined;
}

function extractJktFromAccessToken(accessToken?: string): string | undefined {
  if (!accessToken || accessToken.split('.').length !== 3) return undefined;
  try {
    const claims = decodeJwtPayload(accessToken);
    if (claims.cnf && typeof claims.cnf === 'object' && !Array.isArray(claims.cnf)) {
      const jkt = (claims.cnf as Record<string, unknown>).jkt;
      if (typeof jkt === 'string' && jkt.trim()) {
        return jkt.trim();
      }
    }
  } catch {
    // Ignore non-JWT access token
  }
  return undefined;
}

export function WolinProvider({
  children,
  initialSession = null,
  clientId: defaultClientId,
  redirectUri: defaultRedirectUri,
  defaultOidcIssuer = DEFAULT_WOLIN_OIDC_ISSUER,
  podUrl: defaultPodUrl,
  fetchFn,
  onSessionChange,
}: WolinProviderProps): ReactElement {
  const [session, setSessionState] = useState<WolinSessionState | null>(initialSession);
  const [profile, setProfile] = useState<WebIdProfile | null>(null);
  const [isAuthenticating, setIsAuthenticating] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);

  const inFlightCallbacksRef = useRef<Map<string, Promise<WolinSessionState>>>(new Map());
  const mountedRef = useRef<boolean>(true);
  const authEpochRef = useRef<number>(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const commitSession = useCallback(
    (next: WolinSessionState | null) => {
      if (!mountedRef.current) return;
      setSessionState(next);
      onSessionChange?.(next);
    },
    [onSessionChange],
  );

  // Cleanly restore non-extractable DPoP keypair from IndexedDB if session was hydrated without CryptoKey
  useEffect(() => {
    if (!session || session.tokenType !== 'DPoP' || session.dpopKeyPair) {
      return;
    }
    const targetJkt = session.dpopJkt ?? extractJktFromAccessToken(session.accessToken);
    if (!targetJkt) {
      return;
    }
    let cancelled = false;
    const epochAtStart = authEpochRef.current;
    void loadDpopKeyPairFromIndexedDb(targetJkt).then((restored) => {
      if (
        cancelled ||
        !restored ||
        !mountedRef.current ||
        authEpochRef.current !== epochAtStart
      ) {
        return;
      }
      commitSession({
        ...session,
        dpopKeyPair: restored,
        dpopJkt: restored.jkt,
      });
    });
    return () => {
      cancelled = true;
    };
  }, [session, commitSession]);

  const setSession = useCallback(
    (next: WolinSessionState | null) => {
      authEpochRef.current += 1;
      removeStorageItem(WOLIN_PENDING_AUTH_STORAGE_KEY);
      clearFallbackDpopStorage();
      if (next === null) {
        void clearDpopKeyPairsFromIndexedDb();
      }
      inFlightCallbacksRef.current.clear();
      if (mountedRef.current) {
        setIsAuthenticating(false);
        setError(null);
      }
      commitSession(next);
    },
    [commitSession],
  );

  const client = useMemo(
    () =>
      new WolinPodClient({
        podUrl: session?.podUrl ?? defaultPodUrl,
        webId: session?.webId,
        accessToken: session?.accessToken,
        dpopKeyPair: session?.dpopKeyPair,
        tokenType: session?.tokenType,
        dpopNonce: session?.dpopNonce,
        fetchFn,
      }),
    [
      session?.podUrl,
      session?.webId,
      session?.accessToken,
      session?.dpopKeyPair,
      session?.tokenType,
      session?.dpopNonce,
      defaultPodUrl,
      fetchFn,
    ],
  );

  const login = useCallback(
    async (options?: LoginOptions): Promise<LoginStartResult> => {
      const loginEpoch = ++authEpochRef.current;
      if (mountedRef.current) {
        setIsAuthenticating(true);
        setError(null);
      }
      try {
        const resolvedClientId = options?.clientId ?? defaultClientId;
        const resolvedRedirectUri = options?.redirectUri ?? defaultRedirectUri;
        if (!resolvedClientId || !resolvedRedirectUri) {
          throw new WolinAuthError(
            'clientId and redirectUri must be provided to WolinProvider or login()',
          );
        }
        if (options?.nonce !== undefined && !options.nonce.trim()) {
          throw new WolinAuthError('OIDC nonce parameter must not be empty when provided');
        }

        let resolvedIssuer = options?.oidcIssuer;
        if (!resolvedIssuer && options?.webId) {
          const discoveredProfile = await fetchWebIdProfile(options.webId, { fetchFn });
          if (mountedRef.current && authEpochRef.current === loginEpoch) {
            setProfile(discoveredProfile);
          }
          resolvedIssuer = discoveredProfile.primaryOidcIssuer;
        }
        if (!resolvedIssuer) {
          resolvedIssuer = defaultOidcIssuer;
        }
        if (!resolvedIssuer) {
          throw new WolinAuthError(
            'No Solid-OIDC issuer specified or discovered from WebID profile',
          );
        }

        const providerMetadata = await discoverOidcProvider(resolvedIssuer, { fetchFn });
        const dpopKeyPair = await createAndPersistPendingDpopKeyPair();
        const nonce =
          options?.nonce !== undefined ? options.nonce.trim() : generateRandomState(24);
        const authRequest = await createSolidAuthRequest({
          authorizationEndpoint: providerMetadata.authorization_endpoint,
          clientId: resolvedClientId,
          redirectUri: resolvedRedirectUri,
          scopes: options?.scopes,
          state: options?.state,
          nonce,
          dpopJkt: dpopKeyPair.jkt,
          prompt: options?.prompt,
        });

        if (authEpochRef.current === loginEpoch) {
          savePendingAuthState({
            state: authRequest.state,
            codeVerifier: authRequest.codeVerifier,
            nonce,
            redirectUri: resolvedRedirectUri,
            issuer: providerMetadata.issuer,
            clientId: resolvedClientId,
            tokenEndpoint: providerMetadata.token_endpoint,
            dpopJkt: dpopKeyPair.jkt,
            createdAt: Date.now(),
          });
        } else {
          await deleteDpopKeyPairByJkt(dpopKeyPair.jkt);
        }

        if (
          options?.redirect !== false &&
          typeof window !== 'undefined' &&
          typeof window.location?.assign === 'function'
        ) {
          window.location.assign(authRequest.url);
        }

        return { authRequest, dpopKeyPair, providerMetadata };
      } catch (err) {
        const normalized = err instanceof Error ? err : new Error(String(err));
        if (mountedRef.current && authEpochRef.current === loginEpoch) {
          setError(normalized);
        }
        throw normalized;
      } finally {
        if (mountedRef.current && authEpochRef.current === loginEpoch) {
          setIsAuthenticating(false);
        }
      }
    },
    [defaultClientId, defaultRedirectUri, defaultOidcIssuer, fetchFn],
  );

  const handleRedirectCallback = useCallback(
    async (
      callbackUrl: string,
      overridePending?: PendingSolidAuth,
    ): Promise<WolinSessionState> => {
      const existingInFlight = inFlightCallbacksRef.current.get(callbackUrl);
      if (existingInFlight) {
        return existingInFlight;
      }

      const callbackEpoch = ++authEpochRef.current;
      if (mountedRef.current) {
        setIsAuthenticating(true);
        setError(null);
      }

      const runExchange = async (): Promise<WolinSessionState> => {
        let storedPending: StoredPendingSolidAuth | null = null;
        try {
          if (!overridePending) {
            storedPending = consumePendingAuthState();
            if (!storedPending) {
              throw new WolinAuthError(
                'No pending Solid-OIDC login state found for redirect callback',
              );
            }
          }

          const expectedState = overridePending
            ? overridePending.expectedState
            : storedPending!.state;
          const oidcIssuer = overridePending
            ? overridePending.oidcIssuer
            : storedPending!.issuer;
          const codeVerifier = overridePending
            ? overridePending.codeVerifier
            : storedPending!.codeVerifier;
          const expectedNonce = overridePending
            ? overridePending.nonce
            : storedPending!.nonce || undefined;

          const parsedCallback = new URL(callbackUrl, 'https://localhost');
          const oauthError = parsedCallback.searchParams.get('error');
          if (oauthError) {
            if (storedPending?.dpopJkt) {
              await deleteDpopKeyPairByJkt(storedPending.dpopJkt);
            }
            const desc = parsedCallback.searchParams.get('error_description');
            throw new WolinAuthError(
              `Solid-OIDC authorization failed: ${oauthError}${desc ? ` (${desc})` : ''}`,
            );
          }

          const code = parsedCallback.searchParams.get('code');
          const returnedState = parsedCallback.searchParams.get('state');
          if (!code) {
            if (storedPending?.dpopJkt) {
              await deleteDpopKeyPairByJkt(storedPending.dpopJkt);
            }
            throw new WolinAuthError("Redirect callback URL is missing authorization 'code'");
          }
          if (!expectedState || !expectedState.trim()) {
            if (storedPending?.dpopJkt) {
              await deleteDpopKeyPairByJkt(storedPending.dpopJkt);
            }
            throw new WolinAuthError(
              'Pending Solid-OIDC login state is missing required CSRF expectedState',
            );
          }
          if (!returnedState || returnedState !== expectedState) {
            if (storedPending?.dpopJkt) {
              await deleteDpopKeyPairByJkt(storedPending.dpopJkt);
            }
            throw new WolinAuthError('Solid-OIDC OAuth state mismatch in redirect callback');
          }

          if (!oidcIssuer || !oidcIssuer.trim()) {
            if (storedPending?.dpopJkt) {
              await deleteDpopKeyPairByJkt(storedPending.dpopJkt);
            }
            throw new WolinAuthError(
              'Pending Solid-OIDC login state is missing required oidcIssuer',
            );
          }

          const resolvedClientId =
            (overridePending ? overridePending.clientId : storedPending!.clientId) ||
            defaultClientId;
          const resolvedRedirectUri =
            (overridePending ? overridePending.redirectUri : storedPending!.redirectUri) ||
            defaultRedirectUri;
          if (!resolvedClientId || !resolvedRedirectUri) {
            if (storedPending?.dpopJkt) {
              await deleteDpopKeyPairByJkt(storedPending.dpopJkt);
            }
            throw new WolinAuthError('Missing clientId or redirectUri during callback exchange');
          }

          let dpopKeyPair: DPoPKeyPair;
          if (overridePending) {
            dpopKeyPair = overridePending.dpopKeyPair;
          } else {
            if (!storedPending!.dpopJkt || !storedPending!.dpopJkt.trim()) {
              throw new WolinAuthError(
                'Pending Solid-OIDC login state is missing required dpopJkt binding',
              );
            }
            dpopKeyPair = await restorePendingDpopKeyPair(storedPending!.dpopJkt);
          }

          let tokenEndpoint = overridePending
            ? overridePending.tokenEndpoint
            : storedPending!.tokenEndpoint;
          if (!tokenEndpoint) {
            const discovered = await discoverOidcProvider(oidcIssuer, { fetchFn });
            tokenEndpoint = discovered.token_endpoint;
          }

          const tokenSet = await exchangeCodeForTokens({
            tokenEndpoint,
            code,
            codeVerifier,
            redirectUri: resolvedRedirectUri,
            clientId: resolvedClientId,
            expectedIssuer: oidcIssuer,
            expectedNonce,
            dpopKeyPair,
            fetchFn,
          });

          const webId = tokenSet.webId;
          if (!webId) {
            throw new WolinAuthError(
              'Completed Solid-OIDC token exchange did not yield an IdP-asserted WebID principal',
            );
          }

          const effectiveIssuer =
            extractIssuerFromTokens(tokenSet.idToken, tokenSet.accessToken) ?? oidcIssuer.trim();

          let discoveredPodUrl = defaultPodUrl;
          const verifiedProfile = await fetchWebIdProfile(webId, { fetchFn });
          verifyWebIdOidcIssuer(verifiedProfile, effectiveIssuer);
          if (verifiedProfile.primaryStorage) {
            discoveredPodUrl = verifiedProfile.primaryStorage;
          }

          const normalizedTokenType = normalizeAuthTokenType(tokenSet.tokenType);

          const nextSession: WolinSessionState = {
            webId: verifiedProfile.webId,
            accessToken: tokenSet.accessToken,
            tokenType: normalizedTokenType,
            dpopKeyPair,
            dpopJkt: dpopKeyPair.jkt,
            idToken: tokenSet.idToken,
            refreshToken: tokenSet.refreshToken,
            expiresAt: tokenSet.expiresAt,
            podUrl: discoveredPodUrl,
            oidcIssuer: effectiveIssuer,
            dpopNonce: tokenSet.dpopNonce,
          };

          if (mountedRef.current && authEpochRef.current === callbackEpoch) {
            setProfile(verifiedProfile);
            commitSession(nextSession);
          }

          return nextSession;
        } catch (err) {
          const normalized = err instanceof Error ? err : new Error(String(err));
          if (mountedRef.current && authEpochRef.current === callbackEpoch) {
            setError(normalized);
          }
          throw normalized;
        } finally {
          inFlightCallbacksRef.current.delete(callbackUrl);
          if (mountedRef.current && authEpochRef.current === callbackEpoch) {
            setIsAuthenticating(false);
          }
        }
      };

      const promise = runExchange();
      inFlightCallbacksRef.current.set(callbackUrl, promise);
      return promise;
    },
    [defaultClientId, defaultRedirectUri, defaultPodUrl, fetchFn, commitSession],
  );

  const logout = useCallback(() => {
    authEpochRef.current += 1;
    clearAllPersistedAuthArtifacts();
    inFlightCallbacksRef.current.clear();
    if (mountedRef.current) {
      setProfile(null);
      setError(null);
      setIsAuthenticating(false);
    }
    commitSession(null);
  }, [commitSession]);

  const refreshProfile = useCallback(async (): Promise<WebIdProfile | null> => {
    if (!session?.webId) return null;
    if (!/^https?:\/\//i.test(session.webId)) {
      return null;
    }
    const startEpoch = authEpochRef.current;
    const loaded = await fetchWebIdProfile(session.webId, { fetchFn });
    if (session.oidcIssuer) {
      verifyWebIdOidcIssuer(loaded, session.oidcIssuer);
    }
    if (!mountedRef.current || authEpochRef.current !== startEpoch) {
      return null;
    }
    setProfile(loaded);
    if (loaded.primaryStorage && !session.podUrl) {
      commitSession({
        ...session,
        podUrl: loaded.primaryStorage,
      });
    }
    return loaded;
  }, [session, fetchFn, commitSession]);

  const contextValue = useMemo<WolinContextValue>(
    () => ({
      session,
      profile,
      isAuthenticated: Boolean(session?.accessToken && session.webId),
      isAuthenticating,
      error,
      client,
      login,
      handleRedirectCallback,
      setSession,
      logout,
      refreshProfile,
    }),
    [
      session,
      profile,
      isAuthenticating,
      error,
      client,
      login,
      handleRedirectCallback,
      setSession,
      logout,
      refreshProfile,
    ],
  );

  return <WolinContext.Provider value={contextValue}>{children}</WolinContext.Provider>;
}

/**
 * Access the active Wolin Solid-OIDC + DPoP session, `WolinPodClient`, and auth actions.
 */
export function useWolinSession(): WolinContextValue {
  const ctx = useContext(WolinContext);
  if (!ctx) {
    throw new Error('useWolinSession must be used within a <WolinProvider>');
  }
  return ctx;
}
