import { describe, expect, it, vi } from 'vitest';
import {
  fetchWebIdProfile,
  parseContainerTurtle,
  parseTurtle,
  parseWebIdProfile,
} from '../src/index.js';

const ALICE_WEBID = 'https://alice.wolin.id/profile/card#me';

const WOLIN_PROFILE_TURTLE = `
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
@prefix pim: <http://www.w3.org/ns/pim/space#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .

# Wolin WebID Profile Document
<> a foaf:PersonalProfileDocument ;
   foaf:maker <#me> ;
   foaf:primaryTopic <#me> .

<#me>
    a foaf:Person, vcard:Individual ;
    foaf:name "Alice Moon" ;
    vcard:fn "Alice Moon"@en ;
    pim:storage </> , <https://backup.wolin.id/pods/alice/> ;
    solid:oidcIssuer <https://auth.wolin.id> ;
    ldp:inbox </inbox/> ;
    solid:account [
      a solid:Account ;
      foaf:name "Nested Blank Node Property"
    ] .
`;

describe('@wolin-id/client — WebID Profile & Turtle Parser', () => {
  it('parses WebID profile Turtle with relative IRIs, prefixes, object lists, and blank nodes', () => {
    const profile = parseWebIdProfile(WOLIN_PROFILE_TURTLE, ALICE_WEBID);

    expect(profile.webId).toBe('https://alice.wolin.id/profile/card#me');
    expect(profile.primaryStorage).toBe('https://alice.wolin.id/');
    expect(profile.storages).toEqual([
      'https://alice.wolin.id/',
      'https://backup.wolin.id/pods/alice/',
    ]);
    expect(profile.primaryOidcIssuer).toBe('https://auth.wolin.id');
    expect(profile.oidcIssuers).toEqual(['https://auth.wolin.id']);
    expect(profile.primaryInbox).toBe('https://alice.wolin.id/inbox/');
    expect(profile.inboxes).toEqual(['https://alice.wolin.id/inbox/']);
    expect(profile.name).toBe('Alice Moon');
  });

  it('supports SPARQL-style PREFIX / BASE directives and multiline Turtle literals', () => {
    const sparqlStyleTurtle = `
BASE <https://bob.wolin.id/profile/card>
PREFIX solid: <http://www.w3.org/ns/solid/terms#>
PREFIX pim: <http://www.w3.org/ns/pim/space#>
PREFIX foaf: <http://xmlns.com/foaf/0.1/>

<#me> foaf:name """Bob
Builder""" ;
      pim:storage <../> ;
      solid:oidcIssuer <https://zitadel.wolin.id> .
`;
    const profile = parseWebIdProfile(sparqlStyleTurtle, 'https://bob.wolin.id/profile/card#me');
    expect(profile.primaryStorage).toBe('https://bob.wolin.id/');
    expect(profile.primaryOidcIssuer).toBe('https://zitadel.wolin.id');
    expect(profile.name).toBe('Bob\nBuilder');
  });

  it('dereferences WebID profile over HTTP stripping #me fragment', async () => {
    const mockFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
      new Response(WOLIN_PROFILE_TURTLE, {
        status: 200,
        headers: { 'Content-Type': 'text/turtle; charset=utf-8' },
      }),
    );

    const profile = await fetchWebIdProfile(ALICE_WEBID, { fetchFn: mockFetch });
    expect(mockFetch).toHaveBeenCalledWith(
      'https://alice.wolin.id/profile/card',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Accept: 'text/turtle, application/n-triples;q=0.8',
        }),
      }),
    );
    expect(profile.primaryStorage).toBe('https://alice.wolin.id/');
    expect(profile.primaryOidcIssuer).toBe('https://auth.wolin.id');
  });

  it('extracts ldp:contains children from Solid container Turtle representations', () => {
    const containerTurtle = `
@prefix ldp: <http://www.w3.org/ns/ldp#> .
@prefix pim: <http://www.w3.org/ns/pim/space#> .

<https://alice.wolin.id/> a ldp:BasicContainer, ldp:Container, pim:Storage ;
    ldp:contains <https://alice.wolin.id/profile/>, <https://alice.wolin.id/private/>, <notes.ttl> .
`;
    const triples = parseTurtle(containerTurtle, 'https://alice.wolin.id/');
    expect(triples.length).toBeGreaterThanOrEqual(6);

    const children = parseContainerTurtle(containerTurtle, 'https://alice.wolin.id/');
    expect(children).toEqual([
      'https://alice.wolin.id/notes.ttl',
      'https://alice.wolin.id/private/',
      'https://alice.wolin.id/profile/',
    ]);
  });

  it('extracts wolin:displayName, wolin:avatarGlbUrl, wolin:avatarVrmUrl, and wolin:avatarVariants (IRI and literal)', () => {
    const iriVariantsTurtle = `
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix pim: <http://www.w3.org/ns/pim/space#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix wolin: <https://wolin.id/ns#> .

<#me> a foaf:Person ;
    foaf:name "Alice Full Name" ;
    wolin:displayName "Alice" ;
    pim:storage </> ;
    solid:oidcIssuer <https://auth.wolin.id> ;
    wolin:avatarGlbUrl </public/avatars/default.glb> ;
    wolin:avatarVrmUrl <https://cdn.wolin.id/pods/alice/public/avatar.vrm> ;
    wolin:avatarVariants </public/avatars/variants.json> .
`;
    const iriProfile = parseWebIdProfile(iriVariantsTurtle, ALICE_WEBID);
    expect(iriProfile.name).toBe('Alice Full Name');
    expect(iriProfile.displayName).toBe('Alice');
    expect(iriProfile.avatarGlbUrl).toBe('https://alice.wolin.id/public/avatars/default.glb');
    expect(iriProfile.avatarVrmUrl).toBe('https://cdn.wolin.id/pods/alice/public/avatar.vrm');
    expect(iriProfile.avatarVariants).toBe('https://alice.wolin.id/public/avatars/variants.json');

    const literalVariantsJson = JSON.stringify({
      default: {
        url: 'https://alice.wolin.id/public/avatars/default.vrm',
        format: 'vrm-1.0',
        skeleton: 'vrm-1.0',
        heightMeters: 1.65,
      },
      variants: [
        {
          app: 'jongno',
          catalogId: 'jongno-humanoid-v1',
          skeleton: 'vrm-1.0',
          heightMeters: 1.8,
          url: 'https://alice.wolin.id/public/apps/jongno/avatar.vrm',
        },
      ],
    });

    const literalVariantsTurtle = `
@prefix pim: <http://www.w3.org/ns/pim/space#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix wolin: <https://wolin.id/ns#> .

<#me> wolin:displayName "Wanderer" ;
    pim:storage </> ;
    solid:oidcIssuer <https://auth.wolin.id> ;
    wolin:avatarGlbUrl "https://alice.wolin.id/public/avatar.glb"^^xsd:anyURI ;
    wolin:avatarVrmUrl "https://alice.wolin.id/public/avatar.vrm"^^xsd:anyURI ;
    wolin:avatarVariants '''${literalVariantsJson}''' .
`;
    const literalProfile = parseWebIdProfile(literalVariantsTurtle, ALICE_WEBID);
    expect(literalProfile.displayName).toBe('Wanderer');
    expect(literalProfile.name).toBe('Wanderer');
    expect(literalProfile.avatarGlbUrl).toBe('https://alice.wolin.id/public/avatar.glb');
    expect(literalProfile.avatarVrmUrl).toBe('https://alice.wolin.id/public/avatar.vrm');
    expect(literalProfile.avatarVariants).toBe(literalVariantsJson);
    expect(JSON.parse(literalProfile.avatarVariants!).variants[0].app).toBe('jongno');
  });
});
