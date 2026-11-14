import {
  createSolidAuthRequest,
  type DPoPKeyPair,
  decodeJwtPayload,
  discoverOidcProvider,
  exchangeCodeForTokens,
  fetchWebIdProfile,
  generateDPoPKeyPair,
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

export interface WolinSessionState {
  webId: string;
  accessToken: string;
  tokenType: 'DPoP' | 'Bearer';
  dpopKeyPair?: DPoPKeyPair;
  idToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  podUrl?: string;
  oidcIssuer?: string;
  dpopNonce?: string;
}

export interface LoginOptions {
  /** Explicit Solid-OIDC issuer URL (e.g. `https://id.wolin.id`). */
  oidcIssuer?: string;
  /** User WebID URI from which `solid:oidcIssuer` can be discovered automatically. */
  webId?: string;
  clientId?: string;
  redirectUri?: string;
  scopes?: readonly string[];
  state?: string;
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
  dpopKeyPair: DPoPKeyPair;
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
  defaultOidcIssuer?: string;
  podUrl?: string;
  fetchFn?: typeof fetch;
  onSessionChange?: (session: WolinSessionState | null) => void;
}

export const WolinContext = createContext<WolinContextValue | null>(null);

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

export function WolinProvider({
  children,
  initialSession = null,
  clientId: defaultClientId,
  redirectUri: defaultRedirectUri,
  defaultOidcIssuer,
  podUrl: defaultPodUrl,
  fetchFn,
  onSessionChange,
}: WolinProviderProps): ReactElement {
  const [session, setSessionState] = useState<WolinSessionState | null>(initialSession);
  const [profile, setProfile] = useState<WebIdProfile | null>(null);
  const [isAuthenticating, setIsAuthenticating] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);

  const pendingAuthRef = useRef<PendingSolidAuth | null>(null);
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

  const setSession = useCallback(
    (next: WolinSessionState | null) => {
      authEpochRef.current += 1;
      pendingAuthRef.current = null;
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
        const dpopKeyPair = await generateDPoPKeyPair();
        const authRequest = await createSolidAuthRequest({
          authorizationEndpoint: providerMetadata.authorization_endpoint,
          clientId: resolvedClientId,
          redirectUri: resolvedRedirectUri,
          scopes: options?.scopes,
          state: options?.state,
          prompt: options?.prompt,
        });

        if (authEpochRef.current === loginEpoch) {
          pendingAuthRef.current = {
            codeVerifier: authRequest.codeVerifier,
            expectedState: authRequest.state,
            tokenEndpoint: providerMetadata.token_endpoint,
            oidcIssuer: providerMetadata.issuer,
            clientId: resolvedClientId,
            redirectUri: resolvedRedirectUri,
            dpopKeyPair,
          };
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
        try {
          const pending = overridePending ?? pendingAuthRef.current;
          if (!pending) {
            throw new WolinAuthError(
              'No pending Solid-OIDC login state found for redirect callback',
            );
          }

          const parsedCallback = new URL(callbackUrl, 'https://localhost');
          const oauthError = parsedCallback.searchParams.get('error');
          if (oauthError) {
            const desc = parsedCallback.searchParams.get('error_description');
            throw new WolinAuthError(
              `Solid-OIDC authorization failed: ${oauthError}${desc ? ` (${desc})` : ''}`,
            );
          }

          const code = parsedCallback.searchParams.get('code');
          const returnedState = parsedCallback.searchParams.get('state');
          if (!code) {
            throw new WolinAuthError("Redirect callback URL is missing authorization 'code'");
          }
          if (!pending.expectedState || !pending.expectedState.trim()) {
            throw new WolinAuthError(
              'Pending Solid-OIDC login state is missing required CSRF expectedState',
            );
          }
          if (!returnedState || returnedState !== pending.expectedState) {
            throw new WolinAuthError('Solid-OIDC OAuth state mismatch in redirect callback');
          }

          if (!pending.oidcIssuer || !pending.oidcIssuer.trim()) {
            throw new WolinAuthError(
              'Pending Solid-OIDC login state is missing required oidcIssuer',
            );
          }

          const resolvedClientId = pending.clientId ?? defaultClientId;
          const resolvedRedirectUri = pending.redirectUri ?? defaultRedirectUri;
          if (!resolvedClientId || !resolvedRedirectUri) {
            throw new WolinAuthError('Missing clientId or redirectUri during callback exchange');
          }

          // Consume single-use authorization state synchronously before network await
          if (!overridePending) {
            pendingAuthRef.current = null;
          }

          const tokenSet = await exchangeCodeForTokens({
            tokenEndpoint: pending.tokenEndpoint,
            code,
            codeVerifier: pending.codeVerifier,
            redirectUri: resolvedRedirectUri,
            clientId: resolvedClientId,
            expectedIssuer: pending.oidcIssuer,
            dpopKeyPair: pending.dpopKeyPair,
            fetchFn,
          });

          const webId = tokenSet.webId;
          if (!webId) {
            throw new WolinAuthError(
              'Completed Solid-OIDC token exchange did not yield an IdP-asserted WebID principal',
            );
          }

          const effectiveIssuer =
            extractIssuerFromTokens(tokenSet.idToken, tokenSet.accessToken) ??
            pending.oidcIssuer.trim();

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
            dpopKeyPair: pending.dpopKeyPair,
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
    pendingAuthRef.current = null;
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
