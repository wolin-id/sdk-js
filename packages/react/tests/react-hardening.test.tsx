// @vitest-environment jsdom
import { act, renderHook, waitFor } from '@testing-library/react';
import { type ReactNode, useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { base64UrlEncodeString, generateDPoPKeyPair, WolinAuthError } from '@wolin-id/client';
import { usePodResource, useWolinSession, WolinProvider } from '../src/index.js';

function makeJwt(claims: Record<string, unknown>): string {
  const hdr = base64UrlEncodeString(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
  const pay = base64UrlEncodeString(JSON.stringify(claims));
  const sig = base64UrlEncodeString('sig');
  return `${hdr}.${pay}.${sig}`;
}

describe('@wolin-id/react — Security & Concurrency Hardening', () => {
  it('blocks rogue IdP WebID spoofing when WebID profile does not authorize oidcIssuer', async () => {
    const kp = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      // Token exchange from rogue IdP claiming victim's WebID
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: makeJwt({
              iss: 'https://rogue.idp.example',
              sub: 'victim',
              webid: 'https://victim.wolin.id/profile/card#me',
              aud: 'solid',
              exp: 2_000_000_000,
            }),
            token_type: 'DPoP',
            id_token: makeJwt({
              iss: 'https://rogue.idp.example',
              sub: 'victim',
              webid: 'https://victim.wolin.id/profile/card#me',
              aud: 'https://app.wolin.id/client',
              exp: 2_000_000_000,
            }),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      // Victim's WebID profile only authorizes https://id.wolin.id
      .mockResolvedValueOnce(
        new Response(
          '<#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <https://id.wolin.id> .',
          { status: 200, headers: { 'Content-Type': 'text/turtle' } },
        ),
      );

    const wrapper = ({ children }: { children: ReactNode }) => (
      <WolinProvider
        clientId="https://app.wolin.id/client"
        redirectUri="https://app.wolin.id/cb"
        fetchFn={mockFetch}
      >
        {children}
      </WolinProvider>
    );

    const { result } = renderHook(() => useWolinSession(), { wrapper });

    await expect(
      act(async () => {
        await result.current.handleRedirectCallback(
          'https://app.wolin.id/cb?code=c1&state=csrf-state-1',
          {
            codeVerifier: 'v'.repeat(43),
            expectedState: 'csrf-state-1',
            tokenEndpoint: 'https://rogue.idp.example/token',
            oidcIssuer: 'https://rogue.idp.example',
            dpopKeyPair: kp,
          },
        );
      }),
    ).rejects.toThrow(WolinAuthError);

    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.session).toBeNull();
  });

  it('clears cached private Pod data immediately when url becomes null (e.g. on logout) and updates resource on save', async () => {
    const kp = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response('secret-private-turtle', {
          status: 200,
          headers: { 'Content-Type': 'text/turtle', ETag: '"e1"' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(null, {
          status: 204,
          headers: { ETag: '"e2"' },
        }),
      );

    const wrapper = ({ children }: { children: ReactNode }) => (
      <WolinProvider
        initialSession={{
          webId: 'https://alice.wolin.id/profile/card#me',
          accessToken: 'tok-1',
          tokenType: 'DPoP',
          dpopKeyPair: kp,
          podUrl: 'https://alice.wolin.id/',
        }}
        fetchFn={mockFetch}
      >
        {children}
      </WolinProvider>
    );

    const { result } = renderHook(
      () => {
        const [activeUrl, setActiveUrl] = useState<string | null>('/private/secret.ttl');
        const podRes = usePodResource(activeUrl);
        return { ...podRes, setActiveUrl };
      },
      { wrapper },
    );

    await waitFor(() => {
      expect(result.current.data).toBe('secret-private-turtle');
    });

    await act(async () => {
      await result.current.save('updated-secret-turtle');
    });
    expect(result.current.resource?.etag).toBe('"e2"');
    expect(result.current.resource?.text()).toBe('updated-secret-turtle');

    // Simulate logout setting resource URL to null -> private data MUST be purged immediately
    act(() => {
      result.current.setActiveUrl(null);
    });
    expect(result.current.data).toBeNull();
    expect(result.current.bytes).toBeNull();
    expect(result.current.resource).toBeNull();
    expect(result.current.etag).toBeNull();
  });

  it('enforces WebID solid:oidcIssuer verification even on uppercase HTTPS:// WebID claims', async () => {
    const kp = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: makeJwt({
              iss: 'https://rogue.idp.example',
              sub: 'victim',
              webid: 'HTTPS://victim.wolin.id/profile/card#me',
              aud: 'solid',
              exp: 2_000_000_000,
            }),
            token_type: 'DPoP',
            id_token: makeJwt({
              iss: 'https://rogue.idp.example',
              sub: 'victim',
              webid: 'HTTPS://victim.wolin.id/profile/card#me',
              aud: 'https://app.wolin.id/client',
              exp: 2_000_000_000,
            }),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          '<#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <https://id.wolin.id> .',
          { status: 200, headers: { 'Content-Type': 'text/turtle' } },
        ),
      );

    const wrapper = ({ children }: { children: ReactNode }) => (
      <WolinProvider
        clientId="https://app.wolin.id/client"
        redirectUri="https://app.wolin.id/cb"
        fetchFn={mockFetch}
      >
        {children}
      </WolinProvider>
    );

    const { result } = renderHook(() => useWolinSession(), { wrapper });
    await expect(
      act(async () => {
        await result.current.handleRedirectCallback('https://app.wolin.id/cb?code=c2&state=st2', {
          codeVerifier: 'v'.repeat(43),
          expectedState: 'st2',
          tokenEndpoint: 'https://rogue.idp.example/token',
          oidcIssuer: 'https://rogue.idp.example',
          dpopKeyPair: kp,
        });
      }),
    ).rejects.toThrow(WolinAuthError);
  });
});
