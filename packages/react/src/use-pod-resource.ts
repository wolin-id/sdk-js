import {
  type DeleteResourceOptions,
  type DeleteResourceResult,
  parseLinkHeaderTypes,
  type PodResource,
  type PutResourceOptions,
  WolinHttpError,
  type WriteResourceResult,
} from '@wolin-id/client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useWolinSession } from './provider.js';

export interface UsePodResourceOptions {
  /** Preferred `Accept` header when reading the resource. */
  accept?: string;
  /** Default `Content-Type` when saving string payloads (defaults to `'text/turtle'`). */
  contentType?: string;
  /** Whether automatic initial fetching is enabled (default: `true` when `url` is non-empty). */
  enabled?: boolean;
  /** Send `If-None-Match` with the cached `ETag` on `reload()` (default: `true`). */
  useConditionalGet?: boolean;
}

export interface SavePodResourceOptions extends PutResourceOptions {
  /** Automatically attach `If-Match` with the latest strong `etag` if available (default: `true`). */
  useIfMatch?: boolean;
}

export interface RemovePodResourceOptions extends DeleteResourceOptions {
  /** Automatically attach `If-Match` with the latest strong `etag` if available (default: `true`). */
  useIfMatch?: boolean;
}

export interface UsePodResourceResult {
  resource: PodResource | null;
  data: string | null;
  bytes: Uint8Array | null;
  etag: string | null;
  contentType: string | null;
  isLoading: boolean;
  isSaving: boolean;
  error: Error | null;
  reload: () => Promise<PodResource | null>;
  save: (
    body: string | Uint8Array,
    saveOptions?: SavePodResourceOptions,
  ) => Promise<WriteResourceResult>;
  remove: (removeOptions?: RemovePodResourceOptions) => Promise<DeleteResourceResult>;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8');

function isStrongEtag(etag: string | null): etag is string {
  return Boolean(etag && !etag.trim().startsWith('W/'));
}

/**
 * React hook for reading, conditionally reloading (`If-None-Match` / `304`),
 * saving (`PUT` with `If-Match` optimistic concurrency), and deleting Solid Pod resources.
 */
export function usePodResource(
  url: string | null | undefined,
  options: UsePodResourceOptions = {},
): UsePodResourceResult {
  const { client } = useWolinSession();
  const {
    accept,
    contentType: defaultContentType,
    enabled = true,
    useConditionalGet = true,
  } = options;

  const [resource, setResource] = useState<PodResource | null>(null);
  const [data, setData] = useState<string | null>(null);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [etag, setEtag] = useState<string | null>(null);
  const [contentType, setContentType] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(Boolean(url && enabled));
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);

  const mountedRef = useRef<boolean>(true);
  const etagRef = useRef<string | null>(null);
  const notFoundRef = useRef<boolean>(false);
  const abortRef = useRef<AbortController | null>(null);
  const loadSeqRef = useRef<number>(0);
  const saveSeqRef = useRef<number>(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
    };
  }, []);

  const fetchInternal = useCallback(
    async (conditional: boolean): Promise<PodResource | null> => {
      if (!url) return null;

      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      const seq = ++loadSeqRef.current;

      if (mountedRef.current) {
        setIsLoading(true);
        setError(null);
      }

      try {
        const ifNoneMatch =
          conditional && useConditionalGet && etagRef.current ? etagRef.current : undefined;
        const res = await client.getResource(url, {
          accept,
          ifNoneMatch,
          signal: controller.signal,
        });

        if (!mountedRef.current || seq !== loadSeqRef.current || controller.signal.aborted) {
          return res;
        }

        notFoundRef.current = false;

        if (res.notModified) {
          if (res.etag) {
            etagRef.current = res.etag;
            setEtag(res.etag);
          }
          return res;
        }

        etagRef.current = res.etag;
        setResource(res);
        setBytes(res.bytes);
        setData(res.text());
        setEtag(res.etag);
        setContentType(res.contentType);
        return res;
      } catch (err) {
        if (!mountedRef.current || seq !== loadSeqRef.current || controller.signal.aborted) {
          return null;
        }
        if (err instanceof WolinHttpError && err.status === 404) {
          notFoundRef.current = true;
          etagRef.current = null;
        }
        const normalized = err instanceof Error ? err : new Error(String(err));
        setError(normalized);
        return null;
      } finally {
        if (mountedRef.current && seq === loadSeqRef.current && !controller.signal.aborted) {
          setIsLoading(false);
        }
      }
    },
    [url, client, accept, useConditionalGet],
  );

  useEffect(() => {
    abortRef.current?.abort();
    loadSeqRef.current += 1;
    saveSeqRef.current += 1;
    etagRef.current = null;
    notFoundRef.current = false;

    if (!url || !enabled) {
      setResource(null);
      setData(null);
      setBytes(null);
      setEtag(null);
      setContentType(null);
      setError(null);
      setIsLoading(false);
      setIsSaving(false);
      return;
    }

    setResource(null);
    setData(null);
    setBytes(null);
    setEtag(null);
    setContentType(null);
    setError(null);
    setIsSaving(false);

    void fetchInternal(false);

    return () => {
      abortRef.current?.abort();
    };
  }, [url, enabled, fetchInternal]);

  const reload = useCallback(async (): Promise<PodResource | null> => {
    if (!url) return null;
    return fetchInternal(true);
  }, [url, fetchInternal]);

  const save = useCallback(
    async (
      body: string | Uint8Array,
      saveOptions?: SavePodResourceOptions,
    ): Promise<WriteResourceResult> => {
      if (!url) {
        throw new Error('Cannot save Pod resource when url is null or undefined');
      }

      abortRef.current?.abort();
      loadSeqRef.current += 1;
      const seq = ++saveSeqRef.current;

      if (mountedRef.current) {
        setIsLoading(false);
        setIsSaving(true);
        setError(null);
      }

      try {
        const shouldUseIfMatch = saveOptions?.useIfMatch ?? true;
        const hasExplicitIfNoneMatch = Boolean(saveOptions?.createOnly || saveOptions?.ifNoneMatch);
        const autoIfMatch =
          !hasExplicitIfNoneMatch && shouldUseIfMatch && isStrongEtag(etagRef.current)
            ? etagRef.current
            : undefined;
        const ifMatch = saveOptions?.ifMatch ?? autoIfMatch;

        const autoCreateOnly =
          saveOptions?.createOnly ??
          (!ifMatch && !saveOptions?.ifNoneMatch && shouldUseIfMatch && notFoundRef.current
            ? true
            : undefined);

        const resolvedContentType =
          saveOptions?.contentType ??
          defaultContentType ??
          contentType ??
          (typeof body === 'string' ? 'text/turtle' : 'application/octet-stream');

        const { useIfMatch: _ignored, ...putOpts } = saveOptions ?? {};
        const writeResult = await client.putResource(url, body, {
          ...putOpts,
          contentType: resolvedContentType,
          ifMatch,
          createOnly: autoCreateOnly,
        });

        const nextBytes = typeof body === 'string' ? textEncoder.encode(body) : body;
        const nextText = typeof body === 'string' ? body : textDecoder.decode(body);

        if (mountedRef.current && seq === saveSeqRef.current) {
          notFoundRef.current = false;
          etagRef.current = writeResult.etag;

          const updatedResource: PodResource = {
            url: writeResult.url,
            status: writeResult.status,
            notModified: false,
            etag: writeResult.etag,
            contentType: resolvedContentType,
            linkTypes: parseLinkHeaderTypes(writeResult.headers.get('Link')),
            headers: writeResult.headers,
            bytes: nextBytes,
            text: () => nextText,
            json: <T = unknown>(): T => JSON.parse(nextText) as T,
          };

          setResource(updatedResource);
          setEtag(writeResult.etag);
          setBytes(nextBytes);
          setData(nextText);
          setContentType(resolvedContentType);
        }

        return writeResult;
      } catch (err) {
        const normalized = err instanceof Error ? err : new Error(String(err));
        if (mountedRef.current && seq === saveSeqRef.current) {
          setError(normalized);
        }
        throw normalized;
      } finally {
        if (mountedRef.current && seq === saveSeqRef.current) {
          setIsSaving(false);
        }
      }
    },
    [url, client, defaultContentType, contentType],
  );

  const remove = useCallback(
    async (removeOptions?: RemovePodResourceOptions): Promise<DeleteResourceResult> => {
      if (!url) {
        throw new Error('Cannot delete Pod resource when url is null or undefined');
      }

      abortRef.current?.abort();
      loadSeqRef.current += 1;
      const seq = ++saveSeqRef.current;

      if (mountedRef.current) {
        setIsLoading(false);
        setIsSaving(true);
        setError(null);
      }

      try {
        const shouldUseIfMatch = removeOptions?.useIfMatch ?? true;
        const ifMatch =
          removeOptions?.ifMatch ??
          (shouldUseIfMatch && isStrongEtag(etagRef.current) ? etagRef.current : undefined);

        const { useIfMatch: _ignored, ...delOpts } = removeOptions ?? {};
        const delResult = await client.deleteResource(url, {
          ...delOpts,
          ifMatch,
        });

        if (mountedRef.current && seq === saveSeqRef.current) {
          notFoundRef.current = true;
          etagRef.current = null;
          setResource(null);
          setData(null);
          setBytes(null);
          setEtag(null);
          setContentType(null);
        }

        return delResult;
      } catch (err) {
        const normalized = err instanceof Error ? err : new Error(String(err));
        if (mountedRef.current && seq === saveSeqRef.current) {
          setError(normalized);
        }
        throw normalized;
      } finally {
        if (mountedRef.current && seq === saveSeqRef.current) {
          setIsSaving(false);
        }
      }
    },
    [url, client],
  );

  return {
    resource,
    data,
    bytes,
    etag,
    contentType,
    isLoading,
    isSaving,
    error,
    reload,
    save,
    remove,
  };
}
