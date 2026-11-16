/**
 * Wolin (月印千江) Production Endpoints & Tenant `pod_id` Handle Validation.
 */

/** Canonical Wolin production Solid-OIDC Issuer & Edge Asset Gateway. */
export const DEFAULT_WOLIN_OIDC_ISSUER = 'https://auth.wolin.id';

/** Alias for {@link DEFAULT_WOLIN_OIDC_ISSUER} (`https://auth.wolin.id`). */
export const DEFAULT_WOLIN_ISSUER = DEFAULT_WOLIN_OIDC_ISSUER;

/** Canonical Wolin production multi-tenant Solid Pod Engine endpoint. */
export const DEFAULT_WOLIN_POD_BASE_URL = 'https://pod.wolin.id';

/** Canonical Wolin root domain (`{pod_id}.wolin.id`, e.g. `https://alice.wolin.id`). */
export const DEFAULT_WOLIN_DOMAIN = 'wolin.id';

/** Minimum allowed length for a tenant `pod_id` subdomain label. */
export const MIN_POD_ID_LEN = 3;

/** Maximum allowed length for a tenant `pod_id` subdomain label. */
export const MAX_POD_ID_LEN = 32;

/**
 * Canonical sorted reserved-word blocklist shared identically across
 * `wolin-cloud`, `wolin-engine`, and `@wolin-id/client` (infrastructure,
 * RFC 2142, DNS, mail, OAuth/OIDC, Solid LDP/MCP, and brand/trust handles).
 */
export const RESERVED_POD_ID_LIST = [
  'abuse',
  'admin',
  'administrator',
  'ads',
  'api',
  'app',
  'apps',
  'assets',
  'auth',
  'authorize',
  'autoconfig',
  'autodiscover',
  'backup',
  'beta',
  'billing',
  'blog',
  'calendar',
  'cdn',
  'chat',
  'cloud',
  'consent',
  'console',
  'contact',
  'control',
  'corp',
  'dashboard',
  'data',
  'dev',
  'dns',
  'doc',
  'docs',
  'download',
  'downloads',
  'edge',
  'email',
  'engine',
  'enterprise',
  'entropy',
  'events',
  'files',
  'forum',
  'ftp',
  'gateway',
  'git',
  'graphql',
  'health',
  'healthz',
  'help',
  'home',
  'host',
  'hostmaster',
  'id',
  'idp',
  'images',
  'imap',
  'img',
  'inbox',
  'info',
  'internal',
  'jwks',
  'legal',
  'local',
  'localhost',
  'login',
  'logout',
  'logs',
  'mail',
  'mailer',
  'manage',
  'mcp',
  'media',
  'metrics',
  'mta-sts',
  'mx',
  'net',
  'news',
  'no-reply',
  'noreply',
  'notify',
  'ns',
  'ns1',
  'ns2',
  'ns3',
  'ns4',
  'oauth',
  'official',
  'oidc',
  'ops',
  'org',
  'origin',
  'passport',
  'pay',
  'payment',
  'payments',
  'pod',
  'pods',
  'pop',
  'pop3',
  'portal',
  'postmaster',
  'press',
  'pricing',
  'private',
  'prod',
  'production',
  'profile',
  'proxy',
  'pub',
  'public',
  'register',
  'registry',
  'relay',
  'root',
  'rpc',
  'rss',
  'sandbox',
  'search',
  'secure',
  'security',
  'server',
  'service',
  'services',
  'session',
  'settings',
  'sftp',
  'signin',
  'signout',
  'signup',
  'smtp',
  'solid',
  'sparql',
  'ssh',
  'sso',
  'stage',
  'staging',
  'static',
  'stats',
  'status',
  'storage',
  'store',
  'support',
  'sync',
  'sys',
  'system',
  'team',
  'telemetry',
  'terms',
  'test',
  'testing',
  'token',
  'trust',
  'updates',
  'upload',
  'uploads',
  'userinfo',
  'vault',
  'verify',
  'vpn',
  'wac',
  'web',
  'webhook',
  'webhooks',
  'webid',
  'webmail',
  'webmaster',
  'well-known',
  'wolin',
  'ws',
  'wss',
  'www',
] as const;

export const RESERVED_POD_IDS: ReadonlySet<string> = new Set(RESERVED_POD_ID_LIST);

export type PodIdValidationResult =
  | { valid: true }
  | {
      valid: false;
      code: 'invalid_pod_id' | 'reserved_pod_id';
      reason: string;
    };

export interface ValidatePodIdOptions {
  /**
   * When `true`, skips the reserved infrastructure word check (`RESERVED_POD_IDS`)
   * and validates pure syntactic rules only (`3..32` chars, `[a-z0-9-]`, no `--`, blocks `xn--`).
   * Defaults to `false`.
   */
  allowReserved?: boolean;
}

/**
 * Returns `true` if `podId` is a reserved system/infrastructure handle (e.g. `auth`, `pod`, `admin`).
 */
export function isReservedPodId(podId: string): boolean {
  return typeof podId === 'string' && RESERVED_POD_IDS.has(podId);
}

/**
 * Validate a Wolin (月印千江) tenant `pod_id` subdomain handle:
 * - `3..32` characters (`MIN_POD_ID_LEN`..`MAX_POD_ID_LEN`)
 * - Lowercase ASCII `[a-z0-9-]`, starting and ending with `[a-z0-9]`
 * - Blocks Punycode ACE labels (`xn--`) and consecutive hyphens (`--`)
 * - Blocks reserved system handles (`RESERVED_POD_IDS`) unless `allowReserved: true`
 */
export function validatePodId(
  podId: string,
  options?: ValidatePodIdOptions,
): PodIdValidationResult {
  if (typeof podId !== 'string') {
    return {
      valid: false,
      code: 'invalid_pod_id',
      reason: 'pod_id must be a string',
    };
  }
  if (podId.length < MIN_POD_ID_LEN || podId.length > MAX_POD_ID_LEN) {
    return {
      valid: false,
      code: 'invalid_pod_id',
      reason: `pod_id must be between ${MIN_POD_ID_LEN} and ${MAX_POD_ID_LEN} characters`,
    };
  }
  if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(podId)) {
    return {
      valid: false,
      code: 'invalid_pod_id',
      reason:
        'pod_id must contain only lowercase ASCII [a-z0-9-] and start and end with [a-z0-9]',
    };
  }
  if (podId.startsWith('xn--')) {
    return {
      valid: false,
      code: 'invalid_pod_id',
      reason: "pod_id must not start with Punycode ACE prefix ('xn--')",
    };
  }
  if (podId.includes('--')) {
    return {
      valid: false,
      code: 'invalid_pod_id',
      reason: "pod_id must not contain consecutive hyphens ('--')",
    };
  }
  if (!options?.allowReserved && RESERVED_POD_IDS.has(podId)) {
    return {
      valid: false,
      code: 'reserved_pod_id',
      reason: `pod_id '${podId}' is reserved for system infrastructure`,
    };
  }
  return { valid: true };
}

/**
 * Boolean convenience check for Wolin tenant `pod_id` handles
 * (`3..32` chars, `[a-z0-9-]`, no leading/trailing `-`, no `--`, blocks `xn--` and reserved handles).
 */
export function isValidPodId(podId: string, options?: ValidatePodIdOptions): boolean {
  return validatePodId(podId, options).valid;
}
