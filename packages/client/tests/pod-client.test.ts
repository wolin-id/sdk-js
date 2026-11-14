import { describe, expect, it, vi } from 'vitest';
import {
  generateDPoPKeyPair,
  LDP_BASIC_CONTAINER_IRI,
  verifyDPoPProof,
  WolinHttpError,
  WolinPodClient,
  WolinPreconditionError,
} from '../src/index.js';

describe('@wolin-id/client — WolinPodClient LDP CRUD, DPoP & ETag Support', () => {
  it('attaches valid RFC 9449 Authorization: DPoP + DPoP proof headers on authenticated requests', async () => {
    const keyPair = await generateDPoPKeyPair();
    const accessToken = 'wolin-pod-access-token-live';

    const mockFetch = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      const headers = new Headers(init?.headers);

      expect(headers.get('Authorization')).toBe(`DPoP ${accessToken}`);
      const dpopProof = headers.get('DPoP');
      expect(dpopProof).toBeTruthy();

      const verified = await verifyDPoPProof(dpopProof!, {
        htm: init?.method ?? 'GET',
        htu: url,
        accessToken,
      });
      expect(verified.jkt).toBe(keyPair.jkt);

      return new Response('<#note> <http://purl.org/dc/terms/title> "Hello" .', {
        status: 200,
        headers: {
          'Content-Type': 'text/turtle',
          ETag: '"etag-v1"',
          Link: '<http://www.w3.org/ns/ldp#Resource>; rel="type", <http://www.w3.org/ns/ldp#RDFSource>; rel="type"',
        },
      });
    });

    const client = new WolinPodClient({
      podUrl: 'https://alice.wolin.id/',
      accessToken,
      dpopKeyPair: keyPair,
      fetchFn: mockFetch,
    });

    const res = await client.getResource('/private/note.ttl?view=raw');
    expect(res.status).toBe(200);
    expect(res.notModified).toBe(false);
    expect(res.etag).toBe('"etag-v1"');
    expect(res.contentType).toBe('text/turtle');
    expect(res.linkTypes).toContain('http://www.w3.org/ns/ldp#RDFSource');
    expect(res.text()).toContain('"Hello"');
  });

  it('supports conditional GET with If-None-Match returning 304 Not Modified cleanly', async () => {
    const mockFetch = vi.fn<typeof fetch>().mockImplementation(async (_input, init) => {
      const headers = new Headers(init?.headers);
      expect(headers.get('If-None-Match')).toBe('"etag-v1"');
      return new Response(null, {
        status: 304,
        headers: { ETag: '"etag-v1"' },
      });
    });

    const client = new WolinPodClient({
      podUrl: 'https://alice.wolin.id',
      fetchFn: mockFetch,
    });

    const res = await client.getResource('/public/readme.ttl', { ifNoneMatch: '"etag-v1"' });
    expect(res.status).toBe(304);
    expect(res.notModified).toBe(true);
    expect(res.etag).toBe('"etag-v1"');
    expect(res.bytes.byteLength).toBe(0);
  });

  it('handles PUT with If-Match, createOnly (If-None-Match: *), binary blobs, and 412 Precondition Failed', async () => {
    const keyPair = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      // 1st PUT: createOnly -> 201 Created
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(init?.method).toBe('PUT');
        expect(headers.get('If-None-Match')).toBe('*');
        expect(headers.get('Content-Type')).toBe('application/ld+json');
        return new Response(null, {
          status: 201,
          headers: {
            ETag: '"etag-created-1"',
            Location: 'https://alice.wolin.id/private/profile.jsonld',
          },
        });
      })
      // 2nd PUT: binary Uint8Array with If-Match -> 204 No Content
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(headers.get('If-Match')).toBe('"etag-created-1"');
        expect(headers.get('Content-Type')).toBe('image/png');
        return new Response(null, {
          status: 204,
          headers: { ETag: '"etag-updated-2"' },
        });
      })
      // 3rd PUT: stale ETag -> 412 Precondition Failed
      .mockResolvedValueOnce(
        new Response('ETag mismatch', {
          status: 412,
          statusText: 'Precondition Failed',
        }),
      );

    const client = new WolinPodClient({
      podUrl: 'https://alice.wolin.id/',
      accessToken: 'tok-put',
      dpopKeyPair: keyPair,
      fetchFn: mockFetch,
    });

    const created = await client.putResource(
      '/private/profile.jsonld',
      JSON.stringify({ '@id': 'https://alice.wolin.id/profile/card#me' }),
      { contentType: 'application/ld+json', createOnly: true },
    );
    expect(created.created).toBe(true);
    expect(created.status).toBe(201);
    expect(created.etag).toBe('"etag-created-1"');
    expect(created.location).toBe('https://alice.wolin.id/private/profile.jsonld');

    const updated = await client.putResource(
      '/private/avatar.png',
      new Uint8Array([137, 80, 78, 71]),
      { contentType: 'image/png', ifMatch: '"etag-created-1"' },
    );
    expect(updated.created).toBe(false);
    expect(updated.status).toBe(204);
    expect(updated.etag).toBe('"etag-updated-2"');

    await expect(
      client.putResource('/private/avatar.png', new Uint8Array([1, 2]), {
        ifMatch: '"stale-etag"',
      }),
    ).rejects.toThrow(WolinPreconditionError);
  });

  it('supports createContainer, listContainer, patchResource, postResource, and deleteResource', async () => {
    const keyPair = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      // 1. createContainer (normalizes missing trailing slash + sends BasicContainer Link header)
      .mockImplementationOnce(async (input, init) => {
        const url = String(input);
        const headers = new Headers(init?.headers);
        expect(url).toBe('https://alice.wolin.id/projects/');
        expect(init?.method).toBe('PUT');
        expect(headers.get('Link')).toContain(`<${LDP_BASIC_CONTAINER_IRI}>; rel="type"`);
        return new Response(null, {
          status: 201,
          headers: { ETag: '"etag-dir-1"', Location: url },
        });
      })
      // 2. listContainer (parses ldp:contains and child RDF types)
      .mockResolvedValueOnce(
        new Response(
          `
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://alice.wolin.id/projects/> a ldp:BasicContainer, ldp:Container ;
  ldp:contains <https://alice.wolin.id/projects/spec.ttl>, <https://alice.wolin.id/projects/archive/> .
<https://alice.wolin.id/projects/archive/> a ldp:BasicContainer .
`,
          {
            status: 200,
            headers: { 'Content-Type': 'text/turtle', ETag: '"etag-dir-2"' },
          },
        ),
      )
      // 3. patchResource (SPARQL Update)
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(init?.method).toBe('PATCH');
        expect(headers.get('Content-Type')).toBe('application/sparql-update');
        expect(headers.get('If-Match')).toBe('"etag-spec-1"');
        return new Response(null, { status: 204, headers: { ETag: '"etag-spec-2"' } });
      })
      // 4. postResource (Slug)
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(init?.method).toBe('POST');
        expect(headers.get('Slug')).toBe('task-1.ttl');
        return new Response(null, {
          status: 201,
          headers: {
            Location: 'https://alice.wolin.id/projects/task-1.ttl',
            ETag: '"etag-task-1"',
          },
        });
      })
      // 5. deleteResource with If-Match
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(init?.method).toBe('DELETE');
        expect(headers.get('If-Match')).toBe('"etag-task-1"');
        return new Response(null, { status: 204 });
      });

    const client = new WolinPodClient({
      podUrl: 'https://alice.wolin.id/',
      accessToken: 'tok-crud',
      dpopKeyPair: keyPair,
      fetchFn: mockFetch,
    });

    const dirRes = await client.createContainer('/projects');
    expect(dirRes.created).toBe(true);
    expect(dirRes.url).toBe('https://alice.wolin.id/projects/');

    const listing = await client.listContainer('/projects');
    expect(listing.etag).toBe('"etag-dir-2"');
    expect(listing.uris).toEqual([
      'https://alice.wolin.id/projects/archive/',
      'https://alice.wolin.id/projects/spec.ttl',
    ]);
    const archiveItem = listing.items.find((i) => i.name === 'archive/');
    expect(archiveItem?.isContainer).toBe(true);
    const specItem = listing.items.find((i) => i.name === 'spec.ttl');
    expect(specItem?.isContainer).toBe(false);

    const patched = await client.patchResource(
      '/projects/spec.ttl',
      'INSERT DATA { <#s> <http://purl.org/dc/terms/title> "Updated" . }',
      { ifMatch: '"etag-spec-1"' },
    );
    expect(patched.etag).toBe('"etag-spec-2"');

    const posted = await client.postResource('/projects/', '<#task> a <#Todo> .', {
      slug: 'task-1.ttl',
    });
    expect(posted.location).toBe('https://alice.wolin.id/projects/task-1.ttl');

    const deleted = await client.deleteResource('/projects/task-1.ttl', {
      ifMatch: '"etag-task-1"',
    });
    expect(deleted.status).toBe(204);
  });

  it('retries fetchWithDPoP once when resource server challenges with 401 + DPoP-Nonce', async () => {
    const keyPair = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response('Nonce required', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
            'DPoP-Nonce': 'pod-nonce-abc',
          },
        }),
      )
      .mockImplementationOnce(async (input, init) => {
        const dpop = new Headers(init?.headers).get('DPoP')!;
        const verified = await verifyDPoPProof(dpop, {
          htm: 'GET',
          htu: String(input),
          accessToken: 'tok-nonce',
        });
        expect(verified.nonce).toBe('pod-nonce-abc');
        return new Response('ok', { status: 200 });
      });

    const client = new WolinPodClient({
      accessToken: 'tok-nonce',
      dpopKeyPair: keyPair,
      fetchFn: mockFetch,
    });

    const resp = await client.fetchWithDPoP('https://alice.wolin.id/private/secret.txt');
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe('ok');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('throws WolinHttpError on 404 / 403 responses', async () => {
    const mockFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('Not Found', { status: 404, statusText: 'Not Found' }));

    const client = new WolinPodClient({ fetchFn: mockFetch });
    await expect(client.getResource('https://alice.wolin.id/missing.ttl')).rejects.toThrow(
      WolinHttpError,
    );
  });

  it('invokes globalThis.fetch without leaking WolinPodClient as receiver (Browser Window WebIDL brand safety)', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = async function strictWindowFetch(
        this: unknown,
        _input: RequestInfo | URL,
      ): Promise<Response> {
        if (this !== undefined && this !== globalThis) {
          throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
        }
        return new Response('<#ok> a <#Pass> .', {
          status: 200,
          headers: { 'Content-Type': 'text/turtle', ETag: '"etag-browser-1"' },
        });
      } as typeof fetch;

      const defaultFetchClient = new WolinPodClient({
        podUrl: 'https://alice.wolin.id/',
      });
      const res = await defaultFetchClient.getResource('/public/card.ttl');
      expect(res.etag).toBe('"etag-browser-1"');
      expect(res.text()).toContain('<#Pass>');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
