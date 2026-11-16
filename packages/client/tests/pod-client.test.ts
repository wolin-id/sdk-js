import { describe, expect, it, vi } from 'vitest';
import {
  generateDPoPKeyPair,
  LDP_BASIC_CONTAINER_IRI,
  LDP_NON_RDF_SOURCE_IRI,
  verifyDPoPProof,
  WolinAuthError,
  WolinClient,
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

  it('follows 302 signed R2/CDN asset redirects cleanly via get / getBlob / WolinClient without leaking Authorization or DPoP headers', async () => {
    const keyPair = await generateDPoPKeyPair();
    const secretToken = 'secret-dpop-access-token-never-leak';
    const glbBytes = new Uint8Array([0x67, 0x6c, 0x54, 0x46, 0x02, 0x00, 0x00, 0x00]);
    const signedUrl =
      'https://auth.wolin.id/assets/alice/public/avatar.glb?exp=1893456000&sig=' +
      'a'.repeat(64);

    const mockFetch = vi
      .fn<typeof fetch>()
      // 1st hop: Pod Engine verifies DPoP & returns 302 Found to signed Edge/R2 URL
      .mockImplementationOnce(async (input, init) => {
        expect(String(input)).toBe('https://alice.wolin.id/public/avatar.glb');
        expect(init?.redirect).toBe('manual');
        const headers = new Headers(init?.headers);
        expect(headers.get('Authorization')).toBe(`DPoP ${secretToken}`);
        expect(headers.get('DPoP')).toBeTruthy();

        return new Response(null, {
          status: 302,
          headers: {
            Location: signedUrl,
            ETag: '"etag-glb-pod"',
            Link: `<http://www.w3.org/ns/ldp#Resource>; rel="type", <${LDP_NON_RDF_SOURCE_IRI}>; rel="type"`,
          },
        });
      })
      // 2nd hop: Signed R2/CDN URL MUST NOT receive Authorization or DPoP headers
      .mockImplementationOnce(async (input, init) => {
        expect(String(input)).toBe(signedUrl);
        const headers = new Headers(init?.headers);
        expect(headers.get('Authorization')).toBeNull();
        expect(headers.get('DPoP')).toBeNull();
        expect(headers.get('Cookie')).toBeNull();

        return new Response(glbBytes, {
          status: 200,
          headers: {
            'Content-Type': 'model/gltf-binary',
            ETag: '"etag-glb-r2"',
          },
        });
      })
      // Repeat for getBlob(): 302 -> same-origin presigned URL (still strips credentials!)
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: {
            Location:
              'https://alice.wolin.id/assets/alice/public/avatar.glb?exp=1893456000&sig=' +
              'b'.repeat(64),
          },
        }),
      )
      .mockImplementationOnce(async (_input, init) => {
        const headers = new Headers(init?.headers);
        expect(headers.get('Authorization')).toBeNull();
        expect(headers.get('DPoP')).toBeNull();
        return new Response(glbBytes, {
          status: 200,
          headers: { 'Content-Type': 'model/gltf-binary' },
        });
      });

    const client = new WolinClient({
      podUrl: 'https://alice.wolin.id/',
      accessToken: secretToken,
      dpopKeyPair: keyPair,
      fetchFn: mockFetch,
    });

    const res = await client.get('/public/avatar.glb');
    expect(res.status).toBe(200);
    expect(res.url).toBe('https://alice.wolin.id/public/avatar.glb');
    expect(res.redirectedUrl).toBe(signedUrl);
    expect(res.etag).toBe('"etag-glb-r2"');
    expect(res.contentType).toBe('model/gltf-binary');
    expect(res.linkTypes).toContain(LDP_NON_RDF_SOURCE_IRI);
    expect(res.bytes).toEqual(glbBytes);

    const blob = await client.getBlob('/public/avatar.glb');
    expect(blob.type).toBe('model/gltf-binary');
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(glbBytes);
    expect(mockFetch).toHaveBeenCalledTimes(4);
  });

  it('blocks HTTPS -> HTTP downgrade on 302 asset redirects and re-signs DPoP on same-origin non-presigned redirects', async () => {
    const keyPair = await generateDPoPKeyPair();
    const mockFetch = vi
      .fn<typeof fetch>()
      // 1. HTTPS -> HTTP downgrade must fail closed before following
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { Location: 'http://cdn.wolin.id/assets/alice/avatar.glb?exp=1&sig=2' },
        }),
      )
      // 2. Same-origin Solid container trailing-slash 301 within /pods/alice/ re-signs DPoP with updated htu
      .mockResolvedValueOnce(
        new Response(null, {
          status: 301,
          headers: { Location: '/pods/alice/private/docs/' },
        }),
      )
      .mockImplementationOnce(async (input, init) => {
        expect(String(input)).toBe('https://pod.wolin.id/pods/alice/private/docs/');
        const headers = new Headers(init?.headers);
        expect(headers.get('Authorization')).toBe('DPoP tok-same-origin');
        const verified = await verifyDPoPProof(headers.get('DPoP')!, {
          htm: 'GET',
          htu: 'https://pod.wolin.id/pods/alice/private/docs/',
          accessToken: 'tok-same-origin',
        });
        expect(verified.jkt).toBe(keyPair.jkt);
        return new Response('<#ok> a <#Container> .', {
          status: 200,
          headers: { 'Content-Type': 'text/turtle' },
        });
      })
      // 3. Same-origin redirect escaping /pods/alice/ to /pods/bob/ on shared pod.wolin.id strips credentials!
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { Location: '/pods/bob/public/readme.ttl' },
        }),
      )
      .mockImplementationOnce(async (input, init) => {
        expect(String(input)).toBe('https://pod.wolin.id/pods/bob/public/readme.ttl');
        const headers = new Headers(init?.headers);
        expect(headers.get('Authorization')).toBeNull();
        expect(headers.get('DPoP')).toBeNull();
        return new Response('<#bob> a <#Public> .', {
          status: 200,
          headers: { 'Content-Type': 'text/turtle' },
        });
      });

    const client = new WolinPodClient({
      podUrl: 'https://pod.wolin.id/pods/alice/',
      accessToken: 'tok-same-origin',
      dpopKeyPair: keyPair,
      fetchFn: mockFetch,
    });

    await expect(client.get('/public/avatar.glb')).rejects.toThrow(WolinAuthError);

    const sameOriginRes = await client.get('/private/docs');
    expect(sameOriginRes.status).toBe(200);
    expect(sameOriginRes.redirectedUrl).toBe('https://pod.wolin.id/pods/alice/private/docs/');

    const crossPodRes = await client.get('/public/link-to-bob');
    expect(crossPodRes.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(5);
  });
});
