# `@wolin-id/react`

Official React 18 & 19 bindings for **Wolin (`月印千江`)** Solid Pods via [`@wolin-id/client`](../client).

## Exports

- `<WolinProvider>` — Manages Solid-OIDC + DPoP authentication state (defaulting `defaultOidcIssuer` to `https://auth.wolin.id`), WebID profile discovery (`pim:storage` / `solid:oidcIssuer`), and a memoized `WolinPodClient`.
- `useWolinSession()` — Accesses `{ session, profile, isAuthenticated, isAuthenticating, client, login, handleRedirectCallback, setSession, logout, refreshProfile }`.
- `usePodResource(url, options)` — Reads Solid LDP resources with `AbortController` cleanup, conditional `reload()` (`If-None-Match` -> `304 Not Modified`), optimistic concurrency `save()` (`If-Match`), and `remove()` (`DELETE`).

## License

MIT OR Apache-2.0 — Copyright (c) 2026 [Entropy Paradox, Inc.](https://wolin.id) — Wolin (`月印千江`)
