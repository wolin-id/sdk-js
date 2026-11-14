# `@wolin-id/client`

Zero-dependency TypeScript/JavaScript client for **Wolin W3C Solid 0.11 Pods**, **Solid-OIDC + PKCE**, and **RFC 9449 ES256 DPoP**.

Works natively in modern browsers, Node.js 20+, Cloudflare Workers, Deno, and Bun using standard Web Crypto (`crypto.subtle`) and `fetch`.

## Features

- **RFC 9449 ES256 DPoP**: `generateDPoPKeyPair`, `computeJwkThumbprint` (RFC 7638 canonical SHA-256 `jkt`), `signDPoPProof`, and `verifyDPoPProof` (`htm`, `htu`, `iat`, `jti`, `ath`, `nonce`).
- **Solid-OIDC + PKCE (`S256`)**: `discoverOidcProvider`, `generatePkcePair`, `buildSolidAuthUrl`, `createSolidAuthRequest`, `exchangeCodeForTokens`, and `refreshSolidTokens` (including automatic `use_dpop_nonce` challenge retry).
- **WebID & Turtle Parser**: `fetchWebIdProfile`, `parseWebIdProfile`, `parseTurtle`, and `parseContainerTurtle` extracting `pim:storage`, `solid:oidcIssuer`, `ldp:inbox`, and `ldp:contains`.
- **Solid LDP CRUD + ETag Concurrency**: `WolinPodClient` (`getResource`, `putResource`, `patchResource`, `postResource`, `deleteResource`, `createContainer`, `listContainer`, `fetchWithDPoP`) with `If-Match`, `If-None-Match`, `304 Not Modified`, and `412 Precondition Failed` (`WolinPreconditionError`) support.

## License

MIT OR Apache-2.0 — Copyright (c) 2026 [Entropy Paradox, Inc.](https://wolin.id)
