<div align="center">

# Wolin TypeScript / JavaScript SDK (`@wolin-id/*`)

**Official TypeScript & React SDK for Wolin W3C Solid 0.11 Pods, Solid-OIDC PKCE, and RFC 9449 ES256 DPoP**

**[wolin.id](https://wolin.id)** • **[Wolin Engine (`wolin-id/wolin`)](https://github.com/wolin-id/wolin)**

</div>

---

## Packages

| Package | Description | Runtime Dependencies |
| :--- | :--- | :--- |
| [`@wolin-id/client`](./packages/client) | Core Solid Pod LDP client (`GET`/`PUT`/`POST`/`PATCH`/`DELETE` + `ETag`), Solid-OIDC PKCE helper, WebID Turtle parser, and Web Crypto ES256 DPoP signer | **0** (Web Standards: Browser, Node 20+, Edge Workers) |
| [`@wolin-id/react`](./packages/react) | React 18 & 19 `<WolinProvider>`, `useWolinSession`, and `usePodResource` hooks with ETag conditional reload & optimistic concurrency | `@wolin-id/client` + `react` (peer) |

---

## Quickstart

### 1. Install

```bash
pnpm add @wolin-id/client @wolin-id/react
```

### 2. Core Client (`@wolin-id/client`)

```ts
import {
  WolinPodClient,
  createSolidAuthRequest,
  discoverOidcProvider,
  exchangeCodeForTokens,
  fetchWebIdProfile,
  generateDPoPKeyPair,
} from '@wolin-id/client';

// 1. Discover WebID profile -> pim:storage & solid:oidcIssuer
const profile = await fetchWebIdProfile('https://alice.wolin.id/profile/card#me');
const oidc = await discoverOidcProvider(profile.primaryOidcIssuer!);

// 2. Generate non-extractable ES256 DPoP keypair & Solid-OIDC PKCE URL
const dpopKeyPair = await generateDPoPKeyPair();
const authReq = await createSolidAuthRequest({
  authorizationEndpoint: oidc.authorization_endpoint,
  clientId: 'https://app.example.com/client.jsonld',
  redirectUri: 'https://app.example.com/callback',
});

// 3. Exchange authorization code for DPoP-bound tokens
const tokens = await exchangeCodeForTokens({
  tokenEndpoint: oidc.token_endpoint,
  code: 'authorization-code-from-callback',
  codeVerifier: authReq.codeVerifier,
  redirectUri: authReq.redirectUri,
  clientId: authReq.clientId,
  dpopKeyPair,
});

// 4. Perform ETag-guarded Solid LDP CRUD with automatic DPoP proof signing
const pod = new WolinPodClient({
  podUrl: profile.primaryStorage,
  webId: profile.webId,
  accessToken: tokens.accessToken,
  dpopKeyPair,
});

const created = await pod.putResource(
  '/private/notes.ttl',
  '<#note1> <http://purl.org/dc/terms/title> "Hello Wolin" .',
  { createOnly: true },
);

const note = await pod.getResource('/private/notes.ttl');
await pod.putResource(
  '/private/notes.ttl',
  '<#note1> <http://purl.org/dc/terms/title> "Updated Safely" .',
  { ifMatch: note.etag ?? created.etag ?? undefined },
);
```

### 3. React Integration (`@wolin-id/react`)

```tsx
import { WolinProvider, usePodResource, useWolinSession } from '@wolin-id/react';

export function App() {
  return (
    <WolinProvider
      clientId="https://app.example.com/client.jsonld"
      redirectUri="https://app.example.com/callback"
      defaultOidcIssuer="https://id.wolin.id"
    >
      <NotesEditor />
    </WolinProvider>
  );
}

function NotesEditor() {
  const { isAuthenticated, session, login, logout } = useWolinSession();
  const { data, etag, isLoading, save } = usePodResource(
    isAuthenticated ? '/private/notes.ttl' : null,
  );

  if (!isAuthenticated) {
    return <button onClick={() => void login()}>Sign in with Wolin</button>;
  }

  return (
    <div>
      <p>Signed in as {session?.webId} (ETag: {etag})</p>
      {isLoading ? <p>Loading...</p> : <pre>{data}</pre>}
      <button onClick={() => void save('<#note1> <#done> true .')}>Save with If-Match</button>
      <button onClick={logout}>Sign out</button>
    </div>
  );
}
```

---

## Workspace Development

```bash
pnpm install
pnpm typecheck
pnpm build
pnpm test
```

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))
- MIT License ([LICENSE-MIT](./LICENSE-MIT))

at your option.

Copyright (c) 2026 [Entropy Paradox, Inc.](https://wolin.id) and Wolin Contributors.
