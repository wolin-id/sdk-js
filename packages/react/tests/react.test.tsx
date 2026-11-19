// @vitest-environment jsdom
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  base64UrlEncodeString,
  generateDPoPKeyPair,
  sha256Base64Url,
  verifyDPoPProof,
  WolinAuthError,
} from '@wolin-id/client';
import {
  loadDpopKeyPairFromIndexedDb,
  saveDpopKeyPairToIndexedDb,
  type StoredPendingSolidAuth,
  usePodResource,
  useWolinSession,
  WOLIN_PENDING_AUTH_STORAGE_KEY,
  WolinProvider,
} from '../src/index.js';

function makeJwt(claims: Record<string, unknown>): string {
  const hdr = base64UrlEncodeString(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
  const pay = base64UrlEncodeString(JSON.stringify(claims));
  const sig = base64UrlEncodeString('sig-placeholder');
  return `${hdr}.${pay}.${sig}`;
}

/**
 * Lightweight structured-clone-preserving in-memory IDBFactory shim for jsdom
 * so tests exercise real IndexedDB persistence of non-extractable Web Crypto CryptoKeys.
 */
function createInMemoryIndexedDb(): IDBFactory {
  const databases = new Map<string, Map<string, Map<IDBValidKey, unknown>>>();

  const makeRequest = <T,>(executor: (req: Record<string, unknown>) => void): IDBRequest<T> => {
    const req: Record<string, unknown> = {
      result: undefined,
      error: null,
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
    };
    queueMicrotask(() => executor(req));
    return req as unknown as IDBRequest<T>;
  };

  return {
    open(name: string) {
      return makeRequest<IDBDatabase>((req) => {
        let stores = databases.get(name);
        const isNew = !stores;
        if (!stores) {
          stores = new Map();
          databases.set(name, stores);
        }
        const dbStores = stores;

        const db = {
          objectStoreNames: {
            contains: (storeName: string) => dbStores.has(storeName),
          },
          createObjectStore: (storeName: string) => {
            if (!dbStores.has(storeName)) {
              dbStores.set(storeName, new Map());
            }
            return {} as IDBObjectStore;
          },
          transaction: (storeName: string) => {
            const storeMap = dbStores.get(storeName) ?? new Map<IDBValidKey, unknown>();
            dbStores.set(storeName, storeMap);
            const tx: Record<string, unknown> = {
              error: null,
              oncomplete: null,
              onerror: null,
              onabort: null,
              objectStore: () => ({
                put: (value: unknown, key: IDBValidKey) =>
                  makeRequest((putReq) => {
                    storeMap.set(key, value);
                    putReq.result = key;
                    if (typeof putReq.onsuccess === 'function') putReq.onsuccess({});
                    queueMicrotask(() => {
                      if (typeof tx.oncomplete === 'function') tx.oncomplete({});
                    });
                  }),
                get: (key: IDBValidKey) =>
                  makeRequest((getReq) => {
                    getReq.result = storeMap.get(key);
                    if (typeof getReq.onsuccess === 'function') getReq.onsuccess({});
                    queueMicrotask(() => {
                      if (typeof tx.oncomplete === 'function') tx.oncomplete({});
                    });
                  }),
                delete: (key: IDBValidKey) =>
                  makeRequest((delReq) => {
                    storeMap.delete(key);
                    if (typeof delReq.onsuccess === 'function') delReq.onsuccess({});
                    queueMicrotask(() => {
                      if (typeof tx.oncomplete === 'function') tx.oncomplete({});
                    });
                  }),
                clear: () =>
                  makeRequest((clrReq) => {
                    storeMap.clear();
                    if (typeof clrReq.onsuccess === 'function') clrReq.onsuccess({});
                    queueMicrotask(() => {
                      if (typeof tx.oncomplete === 'function') tx.oncomplete({});
                    });
                  }),
              }),
            };
            return tx as unknown as IDBTransaction;
          },
          close: () => {},
        } as unknown as IDBDatabase;

        req.result = db;
        if (isNew && typeof req.onupgradeneeded === 'function') {
          req.onupgradeneeded({});
        }
        if (typeof req.onsuccess === 'function') {
          req.onsuccess({});
        }
      }) as unknown as IDBOpenDBRequest;
    },
  } as unknown as IDBFactory;
}

describe('@wolin-id/react — WolinProvider, useWolinSession & usePodResource', () => {
  const originalIndexedDb = globalThis.indexedDB;

  beforeEach(() => {
    window.sessionStorage.clear();
    Object.defineProperty(globalThis, 'indexedDB', {
      value: createInMemoryIndexedDb(),
      configurable: true,
      writable: true,
    });
  });

  afterEach(() => {
    window.sessionStorage.clear();
    Object.defineProperty(globalThis, 'indexedDB', {
      value: originalIndexedDb,
      configurable: true,
      writable: true,
    });
  });

  it('throws a clear error when useWolinSession is called outside WolinProvider', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useWolinSession())).toThrow(
      'useWolinSession must be used within a <WolinProvider>',
    );
    consoleSpy.mockRestore();
  });

  it('survives full-page OAuth redirect via sessionStorage PKCE + IndexedDB DPoP keypair and passes dpop_jkt on /authorize', async () => {
    let authorizeUrl: URL | null = null;
    let startedDpopJkt = '';

    const mockFetch = vi
      .fn<typeof fetch>()
      // 1. OIDC discovery during login()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            issuer: 'https://auth.wolin.id',
            authorization_endpoint: 'https://auth.wolin.id/oauth/v2/authorize',
            token_endpoint: 'https://auth.wolin.id/oauth/v2/token',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      // 2. Token exchange on a brand-new WolinProvider instance after simulated full-page redirect
      .mockImplementationOnce(async (input, init) => {
        const headers = new Headers(init?.headers);
        const dpopHeader = headers.get('DPoP');
        expect(dpopHeader).toBeTruthy();

        const verifiedProof = await verifyDPoPProof(dpopHeader!, {
          htm: 'POST',
          htu: String(input),
        });
        // DPoP proof jkt on /token MUST match dpop_jkt sent on /authorize!
        expect(verifiedProof.jkt).toBe(startedDpopJkt);

        const bodyParams = new URLSearchParams(String(init?.body));
        const verifier = bodyParams.get('code_verifier')!;
        expect(await sha256Base64Url(verifier)).toBe(
          authorizeUrl!.searchParams.get('code_challenge'),
        );

        const idToken = makeJwt({
          iss: 'https://auth.wolin.id',
          sub: 'alice',
          webid: 'https://alice.wolin.id/profile/card#me',
          aud: 'https://app.wolin.id/client',
          nonce: authorizeUrl!.searchParams.get('nonce'),
          exp: 2_000_000_000,
        });
        const accessToken = makeJwt({
          iss: 'https://auth.wolin.id',
          sub: 'alice',
          webid: 'https://alice.wolin.id/profile/card#me',
          aud: 'solid',
          cnf: { jkt: startedDpopJkt },
          exp: 2_000_000_000,
        });
        return new Response(
          JSON.stringify({
            access_token: accessToken,
            token_type: 'DPoP',
            id_token: idToken,
            expires_in: 3600,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      })
      // 3. WebID Profile dereference with wolin:* predicates
      .mockResolvedValueOnce(
        new Response(
          `
@prefix pim: <http://www.w3.org/ns/pim/space#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix wolin: <https://wolin.id/ns#> .
<#me> foaf:name "Alice Kim" ;
      wolin:displayName "Alice" ;
      wolin:avatarGlbUrl </public/avatar.glb> ;
      wolin:avatarVrmUrl </public/avatar.vrm> ;
      wolin:avatarVariants </public/avatars/variants.json> ;
      pim:storage <https://alice.wolin.id/> ;
      solid:oidcIssuer <https://auth.wolin.id> .
`,
          { status: 200, headers: { 'Content-Type': 'text/turtle' } },
        ),
      );

    const makeWrapper = () =>
      function Wrapper({ children }: { children: ReactNode }) {
        return (
          <WolinProvider
            clientId="https://app.wolin.id/client"
            redirectUri="https://app.wolin.id/cb"
            defaultOidcIssuer="https://auth.wolin.id"
            fetchFn={mockFetch}
          >
            {children}
          </WolinProvider>
        );
      };

    // Mount Provider #1 (pre-redirect page)
    const firstMount = renderHook(() => useWolinSession(), { wrapper: makeWrapper() });
    expect(firstMount.result.current.isAuthenticated).toBe(false);

    await act(async () => {
      const started = await firstMount.result.current.login({ redirect: false });
      authorizeUrl = new URL(started.authRequest.url);
      startedDpopJkt = started.dpopKeyPair.jkt;
      expect(started.dpopKeyPair.privateKey.extractable).toBe(false);
    });

    // Verify /authorize URL contains PKCE + nonce + dpop_jkt
    expect(authorizeUrl!.origin + authorizeUrl!.pathname).toBe(
      'https://auth.wolin.id/oauth/v2/authorize',
    );
    expect(authorizeUrl!.searchParams.get('dpop_jkt')).toBe(startedDpopJkt);
    expect(authorizeUrl!.searchParams.get('nonce')).toBeTruthy();
    expect(authorizeUrl!.searchParams.get('code_challenge_method')).toBe('S256');

    // Verify sessionStorage persisted pending PKCE state WITHOUT private JWK material
    const rawStored = window.sessionStorage.getItem(WOLIN_PENDING_AUTH_STORAGE_KEY);
    expect(rawStored).toBeTruthy();
    expect(rawStored).not.toContain('"d"');
    const parsedStored = JSON.parse(rawStored!) as StoredPendingSolidAuth;
    expect(parsedStored.state).toBe(authorizeUrl!.searchParams.get('state'));
    expect(parsedStored.nonce).toBe(authorizeUrl!.searchParams.get('nonce'));
    expect(parsedStored.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(parsedStored.redirectUri).toBe('https://app.wolin.id/cb');
    expect(parsedStored.issuer).toBe('https://auth.wolin.id');
    expect(parsedStored.clientId).toBe('https://app.wolin.id/client');
    expect(parsedStored.dpopJkt).toBe(startedDpopJkt);

    // Verify IndexedDB holds the non-extractable DPoPKeyPair
    const idbKeyPair = await loadDpopKeyPairFromIndexedDb(startedDpopJkt);
    expect(idbKeyPair?.jkt).toBe(startedDpopJkt);
    expect(idbKeyPair?.privateKey.extractable).toBe(false);

    // Simulate full-page OAuth redirect by completely unmounting Provider #1
    firstMount.unmount();

    // Mount a fresh Provider #2 on /cb?code=...&state=... (all React refs reset)
    const secondMount = renderHook(() => useWolinSession(), { wrapper: makeWrapper() });
    expect(secondMount.result.current.session).toBeNull();

    await act(async () => {
      await secondMount.result.current.handleRedirectCallback(
        `https://app.wolin.id/cb?code=code-abc&state=${encodeURIComponent(parsedStored.state)}`,
      );
    });

    // Pending sessionStorage state must be single-use and consumed immediately
    expect(window.sessionStorage.getItem(WOLIN_PENDING_AUTH_STORAGE_KEY)).toBeNull();

    expect(secondMount.result.current.isAuthenticated).toBe(true);
    expect(secondMount.result.current.session?.webId).toBe(
      'https://alice.wolin.id/profile/card#me',
    );
    expect(secondMount.result.current.session?.podUrl).toBe('https://alice.wolin.id/');
    expect(secondMount.result.current.session?.dpopKeyPair?.jkt).toBe(startedDpopJkt);
    expect(secondMount.result.current.profile?.name).toBe('Alice Kim');
    expect(secondMount.result.current.profile?.displayName).toBe('Alice');
    expect(secondMount.result.current.profile?.avatarGlbUrl).toBe(
      'https://alice.wolin.id/public/avatar.glb',
    );
    expect(secondMount.result.current.profile?.avatarVrmUrl).toBe(
      'https://alice.wolin.id/public/avatar.vrm',
    );
    expect(secondMount.result.current.profile?.avatarVariants).toBe(
      'https://alice.wolin.id/public/avatars/variants.json',
    );

    // Replaying the consumed callback URL must fail closed
    let replayErr: unknown;
    await act(async () => {
      try {
        await secondMount.result.current.handleRedirectCallback(
          `https://app.wolin.id/cb?code=code-abc&state=${encodeURIComponent(parsedStored.state)}`,
        );
      } catch (err) {
        replayErr = err;
      }
    });
    expect(replayErr).toBeInstanceOf(WolinAuthError);

    // Logout clears session, profile, and IndexedDB DPoP keys
    act(() => {
      secondMount.result.current.logout();
    });
    expect(secondMount.result.current.isAuthenticated).toBe(false);
    expect(secondMount.result.current.session).toBeNull();
    expect(secondMount.result.current.profile).toBeNull();
    await waitFor(async () => {
      expect(await loadDpopKeyPairFromIndexedDb(startedDpopJkt)).toBeNull();
    });
  });

  it('cleanly restores DPoP keypair across redirect even when IndexedDB is unavailable and restores hydrated session keypair from IndexedDB', async () => {
    // Part A: Disable IndexedDB to verify clean JWK fallback restoration across full unmount/remount
    Object.defineProperty(globalThis, 'indexedDB', {
      value: undefined,
      configurable: true,
      writable: true,
    });

    let authUrl: URL | null = null;
    let expectedJkt = '';

    const mockFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            issuer: 'https://auth.wolin.id',
            authorization_endpoint: 'https://auth.wolin.id/oauth/v2/authorize',
            token_endpoint: 'https://auth.wolin.id/oauth/v2/token',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockImplementationOnce(async (input, init) => {
        const dpop = new Headers(init?.headers).get('DPoP')!;
        const verified = await verifyDPoPProof(dpop, { htm: 'POST', htu: String(input) });
        expect(verified.jkt).toBe(expectedJkt);
        return new Response(
          JSON.stringify({
            access_token: makeJwt({
              iss: 'https://auth.wolin.id',
              sub: 'alice',
              webid: 'https://alice.wolin.id/profile/card#me',
              aud: 'solid',
              cnf: { jkt: expectedJkt },
              exp: 2_000_000_000,
            }),
            token_type: 'DPoP',
            id_token: makeJwt({
              iss: 'https://auth.wolin.id',
              sub: 'alice',
              webid: 'https://alice.wolin.id/profile/card#me',
              aud: 'https://app.wolin.id/client',
              nonce: authUrl!.searchParams.get('nonce'),
              exp: 2_000_000_000,
            }),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      })
      .mockResolvedValueOnce(
        new Response(
          '<#me> <http://www.w3.org/ns/pim/space#storage> <https://alice.wolin.id/> ; <http://www.w3.org/ns/solid/terms#oidcIssuer> <https://auth.wolin.id> .',
          { status: 200, headers: { 'Content-Type': 'text/turtle' } },
        ),
      );

    const makeWrapper = () =>
      function Wrapper({ children }: { children: ReactNode }) {
        return (
          <WolinProvider
            clientId="https://app.wolin.id/client"
            redirectUri="https://app.wolin.id/cb"
            fetchFn={mockFetch}
          >
            {children}
          </WolinProvider>
        );
      };

    const m1 = renderHook(() => useWolinSession(), { wrapper: makeWrapper() });
    await act(async () => {
      const started = await m1.result.current.login({ redirect: false });
      authUrl = new URL(started.authRequest.url);
      expectedJkt = started.dpopKeyPair.jkt;
      expect(started.dpopKeyPair.privateKey.extractable).toBe(false);
    });
    m1.unmount();

    const m2 = renderHook(() => useWolinSession(), { wrapper: makeWrapper() });
    await act(async () => {
      await m2.result.current.handleRedirectCallback(
        `https://app.wolin.id/cb?code=c-fallback&state=${encodeURIComponent(
          authUrl!.searchParams.get('state')!,
        )}`,
      );
    });
    expect(m2.result.current.session?.dpopKeyPair?.jkt).toBe(expectedJkt);
    expect(m2.result.current.session?.dpopKeyPair?.privateKey.extractable).toBe(false);
    expect(window.sessionStorage.length).toBe(0);
    m2.unmount();

    // Part B: Re-enable IndexedDB and verify hydrated initialSession automatically restores DPoPKeyPair
    Object.defineProperty(globalThis, 'indexedDB', {
      value: createInMemoryIndexedDb(),
      configurable: true,
      writable: true,
    });
    const persistedKp = await generateDPoPKeyPair({ extractable: false });
    await saveDpopKeyPairToIndexedDb(persistedKp, true);

    const hydratedWrapper = ({ children }: { children: ReactNode }) => (
      <WolinProvider
        initialSession={{
          webId: 'https://alice.wolin.id/profile/card#me',
          accessToken: 'hydrated-token',
          tokenType: 'DPoP',
          dpopJkt: persistedKp.jkt,
          podUrl: 'https://alice.wolin.id/',
        }}
        fetchFn={mockFetch}
      >
        {children}
      </WolinProvider>
    );
    const m3 = renderHook(() => useWolinSession(), { wrapper: hydratedWrapper });
    await waitFor(() => {
      expect(m3.result.current.session?.dpopKeyPair?.jkt).toBe(persistedKp.jkt);
    });
  });

  it('fetches, conditionally reloads (304 Not Modified), saves with If-Match ETag, and deletes via usePodResource', async () => {
    const keyPair = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      // 1. Initial GET -> 200 OK with ETag "v1"
      .mockResolvedValueOnce(
        new Response('<#todo> <#title> "Initial" .', {
          status: 200,
          headers: { 'Content-Type': 'text/turtle', ETag: '"v1"' },
        }),
      )
      // 2. Conditional reload -> sends If-None-Match: "v1", receives 304 Not Modified
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(headers.get('If-None-Match')).toBe('"v1"');
        return new Response(null, {
          status: 304,
          headers: { ETag: '"v1"' },
        });
      })
      // 3. save() -> sends PUT with If-Match: "v1", receives 204 No Content with ETag "v2"
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(init?.method).toBe('PUT');
        expect(headers.get('If-Match')).toBe('"v1"');
        expect(headers.get('Authorization')).toBe('DPoP tok-session-1');
        expect(headers.get('DPoP')).toBeTruthy();
        return new Response(null, {
          status: 204,
          headers: { ETag: '"v2"' },
        });
      })
      // 4. remove() -> sends DELETE with If-Match: "v2", receives 204 No Content
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(init?.method).toBe('DELETE');
        expect(headers.get('If-Match')).toBe('"v2"');
        return new Response(null, { status: 204 });
      });

    function NoteView() {
      const { data, etag, isLoading, reload, save, remove } = usePodResource('/private/todo.ttl');
      return (
        <div>
          <span data-testid="loading">{String(isLoading)}</span>
          <span data-testid="etag">{etag ?? 'none'}</span>
          <span data-testid="data">{data ?? 'empty'}</span>
          <button type="button" onClick={() => void reload()}>
            Reload
          </button>
          <button type="button" onClick={() => void save('<#todo> <#title> "Updated" .')}>
            Save
          </button>
          <button type="button" onClick={() => void remove()}>
            Delete
          </button>
        </div>
      );
    }

    render(
      <WolinProvider
        initialSession={{
          webId: 'https://alice.wolin.id/profile/card#me',
          accessToken: 'tok-session-1',
          tokenType: 'DPoP',
          dpopKeyPair: keyPair,
          podUrl: 'https://alice.wolin.id/',
        }}
        fetchFn={mockFetch}
      >
        <NoteView />
      </WolinProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
      expect(screen.getByTestId('etag').textContent).toBe('"v1"');
    });
    expect(screen.getByTestId('data').textContent).toBe('<#todo> <#title> "Initial" .');

    // Trigger conditional reload -> 304 keeps existing data
    await act(async () => {
      screen.getByText('Reload').click();
    });
    expect(screen.getByTestId('data').textContent).toBe('<#todo> <#title> "Initial" .');
    expect(screen.getByTestId('etag').textContent).toBe('"v1"');

    // Trigger optimistic save -> PUT with If-Match "v1", updates data & ETag to "v2"
    await act(async () => {
      screen.getByText('Save').click();
    });
    await waitFor(() => {
      expect(screen.getByTestId('etag').textContent).toBe('"v2"');
    });
    expect(screen.getByTestId('data').textContent).toBe('<#todo> <#title> "Updated" .');

    // Trigger remove -> DELETE with If-Match "v2", clears local resource state
    await act(async () => {
      screen.getByText('Delete').click();
    });
    await waitFor(() => {
      expect(screen.getByTestId('etag').textContent).toBe('none');
    });
    expect(screen.getByTestId('data').textContent).toBe('empty');
  });
});
