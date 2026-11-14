// @vitest-environment jsdom
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { base64UrlEncodeString, generateDPoPKeyPair } from '@wolin-id/client';
import { usePodResource, useWolinSession, WolinProvider } from '../src/index.js';

function makeJwt(claims: Record<string, unknown>): string {
  const hdr = base64UrlEncodeString(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
  const pay = base64UrlEncodeString(JSON.stringify(claims));
  const sig = base64UrlEncodeString('sig-placeholder');
  return `${hdr}.${pay}.${sig}`;
}

describe('@wolin-id/react — WolinProvider, useWolinSession & usePodResource', () => {
  it('throws a clear error when useWolinSession is called outside WolinProvider', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useWolinSession())).toThrow(
      'useWolinSession must be used within a <WolinProvider>',
    );
    consoleSpy.mockRestore();
  });

  it('completes login -> PKCE/DPoP callback -> profile pim:storage discovery -> logout flow', async () => {
    const mockFetch = vi
      .fn<typeof fetch>()
      // 1. OIDC discovery
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            issuer: 'https://id.wolin.id',
            authorization_endpoint: 'https://id.wolin.id/oauth/v2/authorize',
            token_endpoint: 'https://id.wolin.id/oauth/v2/token',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      // 2. Token exchange
      .mockImplementationOnce(async () => {
        const idToken = makeJwt({
          iss: 'https://id.wolin.id',
          sub: 'alice',
          webid: 'https://alice.wolin.id/profile/card#me',
          aud: 'https://app.wolin.id/client',
          exp: 2_000_000_000,
        });
        const accessToken = makeJwt({
          iss: 'https://id.wolin.id',
          sub: 'alice',
          webid: 'https://alice.wolin.id/profile/card#me',
          aud: 'solid',
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
      // 3. WebID Profile dereference
      .mockResolvedValueOnce(
        new Response(
          `
@prefix pim: <http://www.w3.org/ns/pim/space#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<#me> foaf:name "Alice" ;
      pim:storage <https://alice.wolin.id/> ;
      solid:oidcIssuer <https://id.wolin.id> .
`,
          { status: 200, headers: { 'Content-Type': 'text/turtle' } },
        ),
      );

    const wrapper = ({ children }: { children: ReactNode }) => (
      <WolinProvider
        clientId="https://app.wolin.id/client"
        redirectUri="https://app.wolin.id/cb"
        defaultOidcIssuer="https://id.wolin.id"
        fetchFn={mockFetch}
      >
        {children}
      </WolinProvider>
    );

    const { result } = renderHook(() => useWolinSession(), { wrapper });
    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.session).toBeNull();

    let loginState = '';
    await act(async () => {
      const started = await result.current.login({ redirect: false });
      loginState = started.authRequest.state;
      expect(started.authRequest.url).toContain('https://id.wolin.id/oauth/v2/authorize');
      expect(started.dpopKeyPair.jkt.length).toBeGreaterThan(10);
    });

    await act(async () => {
      await result.current.handleRedirectCallback(
        `https://app.wolin.id/cb?code=code-abc&state=${encodeURIComponent(loginState)}`,
      );
    });

    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.session?.webId).toBe('https://alice.wolin.id/profile/card#me');
    expect(result.current.session?.podUrl).toBe('https://alice.wolin.id/');
    expect(result.current.profile?.name).toBe('Alice');

    act(() => {
      result.current.logout();
    });
    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.session).toBeNull();
    expect(result.current.profile).toBeNull();
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
