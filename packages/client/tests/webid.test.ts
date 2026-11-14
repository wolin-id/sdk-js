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
    solid:oidcIssuer <https://id.wolin.id> ;
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
    expect(profile.primaryOidcIssuer).toBe('https://id.wolin.id');
    expect(profile.oidcIssuers).toEqual(['https://id.wolin.id']);
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
    expect(profile.primaryOidcIssuer).toBe('https://id.wolin.id');
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
});
