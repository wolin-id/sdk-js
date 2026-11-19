# `@wolin-id/client`

Zero-dependency TypeScript/JavaScript client for **Wolin (`月印千江`) W3C Solid 0.11 Pods**, **Solid-OIDC + PKCE**, and **RFC 9449 ES256 DPoP**.

Works natively in modern browsers, Node.js 20+, Cloudflare Workers, Deno, and Bun using standard Web Crypto (`crypto.subtle`) and `fetch`.

## Production Endpoints

- **Solid-OIDC Issuer & Signed Asset Gateway**: `https://auth.wolin.id` (`DEFAULT_WOLIN_OIDC_ISSUER`)
- **Multi-Tenant Solid Pod Engine**: `https://pod.wolin.id` (`DEFAULT_WOLIN_POD_BASE_URL`)
- **Tenant Pod Subdomain & WebID**: `https://alice.wolin.id` (`https://alice.wolin.id/profile/card#me`)

## Features

- **RFC 9449 ES256 DPoP**: `generateDPoPKeyPair`, `computeJwkThumbprint` (RFC 7638 canonical SHA-256 `jkt`), `signDPoPProof`, and `verifyDPoPProof` (`htm`, `htu`, `iat`, `jti`, `ath`, `nonce`).
- **Solid-OIDC + PKCE (`S256`)**: `discoverOidcProvider`, `generatePkcePair`, `buildSolidAuthUrl`, `createSolidAuthRequest`, `exchangeCodeForTokens`, and `refreshSolidTokens` (including automatic `use_dpop_nonce` challenge retry).
- **WebID & Turtle Parser**: `fetchWebIdProfile`, `parseWebIdProfile`, `parseTurtle`, and `parseContainerTurtle` extracting `pim:storage`, `solid:oidcIssuer`, `ldp:inbox`, `wolin:displayName`, `wolin:avatarGlbUrl`, `wolin:avatarVrmUrl`, `wolin:avatarVariants` (IRI or literal), and `ldp:contains`.
- **Tenant `pod_id` Handle Validation**: `isValidPodId`, `validatePodId`, `isReservedPodId`, and `RESERVED_POD_IDS` (`3..32` lowercase `[a-z0-9-]`, no leading/trailing `-`, no `--`, blocks `xn--` Punycode and reserved system handles).
- **Solid LDP CRUD, Binary Blobs & Safe `302` Signed Redirects**: `WolinPodClient` (aliased as `WolinClient`) with `getResource` / `get`, `getBlob`, `putResource`, `patchResource`, `postResource`, `deleteResource`, `createContainer`, `listContainer`, and `fetchWithDPoP` — enforcing `If-Match` / `If-None-Match` (`304 Not Modified`, `412 Precondition Failed` via `WolinPreconditionError`) and stripping `Authorization` / `DPoP` headers when following `302` signed R2/CDN asset redirects.

## License

MIT OR Apache-2.0 — Copyright (c) 2026 [Entropy Paradox, Inc.](https://wolin.id) — Wolin (`月印千江`)
