import { WolinAuthError, WolinParseError } from './errors.js';

export const RDF_TYPE_IRI = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
export const RDF_FIRST_IRI = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#first';
export const RDF_REST_IRI = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#rest';
export const RDF_NIL_IRI = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#nil';
export const XSD_STRING_IRI = 'http://www.w3.org/2001/XMLSchema#string';
export const XSD_BOOLEAN_IRI = 'http://www.w3.org/2001/XMLSchema#boolean';
export const XSD_INTEGER_IRI = 'http://www.w3.org/2001/XMLSchema#integer';
export const XSD_DECIMAL_IRI = 'http://www.w3.org/2001/XMLSchema#decimal';
export const XSD_DOUBLE_IRI = 'http://www.w3.org/2001/XMLSchema#double';
export const RDF_LANG_STRING_IRI = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#langString';

export const SOLID_OIDC_ISSUER_IRI = 'http://www.w3.org/ns/solid/terms#oidcIssuer';
export const PIM_STORAGE_IRI = 'http://www.w3.org/ns/pim/space#storage';
export const PIM_STORAGE_CLASS_IRI = 'http://www.w3.org/ns/pim/space#Storage';
export const LDP_INBOX_IRI = 'http://www.w3.org/ns/ldp#inbox';
export const LDP_CONTAINS_IRI = 'http://www.w3.org/ns/ldp#contains';
export const LDP_RESOURCE_IRI = 'http://www.w3.org/ns/ldp#Resource';
export const LDP_RDF_SOURCE_IRI = 'http://www.w3.org/ns/ldp#RDFSource';
export const LDP_NON_RDF_SOURCE_IRI = 'http://www.w3.org/ns/ldp#NonRDFSource';
export const LDP_CONTAINER_IRI = 'http://www.w3.org/ns/ldp#Container';
export const LDP_BASIC_CONTAINER_IRI = 'http://www.w3.org/ns/ldp#BasicContainer';
export const FOAF_NAME_IRI = 'http://xmlns.com/foaf/0.1/name';
export const VCARD_FN_IRI = 'http://www.w3.org/2006/vcard/ns#fn';

const SUPPORTED_TURTLE_MEDIA_TYPES = new Set([
  '',
  'text/turtle',
  'application/x-turtle',
  'text/n3',
  'application/n-triples',
  'text/plain',
]);

export interface RdfTriple {
  subject: string;
  predicate: string;
  object: string;
  objectType: 'iri' | 'literal' | 'blank';
  datatype?: string;
  language?: string;
}

export interface WebIdProfile {
  webId: string;
  oidcIssuers: string[];
  storages: string[];
  inboxes: string[];
  name?: string;
  primaryStorage?: string;
  primaryOidcIssuer?: string;
  primaryInbox?: string;
  triples: RdfTriple[];
}

type Token =
  | { kind: 'punct'; value: '.' | ';' | ',' | '[' | ']' | '(' | ')' }
  | { kind: 'iri'; value: string }
  | { kind: 'pname'; prefix: string; local: string }
  | { kind: 'bnode'; label: string }
  | { kind: 'literal'; value: string; language?: string; datatypeToken?: Token }
  | { kind: 'word'; value: string };

function decodeUnicodeScalarEscape(hex: string, prefix: 'u' | 'U'): string {
  const codePoint = Number.parseInt(hex, 16);
  if (
    !Number.isFinite(codePoint) ||
    codePoint < 0 ||
    codePoint > 0x10ffff ||
    (codePoint >= 0xd800 && codePoint <= 0xdfff)
  ) {
    throw new WolinParseError(
      `Invalid Unicode scalar value '\\${prefix}${hex}' in Turtle document`,
    );
  }
  return String.fromCodePoint(codePoint);
}

function unescapeTurtleString(raw: string): string {
  let out = '';
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (ch !== '\\') {
      out += ch;
      continue;
    }
    i++;
    if (i >= raw.length) {
      throw new WolinParseError('Unterminated escape sequence in Turtle string');
    }
    const esc = raw[i]!;
    switch (esc) {
      case 't':
        out += '\t';
        break;
      case 'b':
        out += '\b';
        break;
      case 'n':
        out += '\n';
        break;
      case 'r':
        out += '\r';
        break;
      case 'f':
        out += '\f';
        break;
      case '"':
        out += '"';
        break;
      case "'":
        out += "'";
        break;
      case '\\':
        out += '\\';
        break;
      case 'u': {
        const hex = raw.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          throw new WolinParseError(`Invalid \\u escape '\\u${hex}' in Turtle`);
        }
        out += decodeUnicodeScalarEscape(hex, 'u');
        i += 4;
        break;
      }
      case 'U': {
        const hex = raw.slice(i + 1, i + 9);
        if (!/^[0-9a-fA-F]{8}$/.test(hex)) {
          throw new WolinParseError(`Invalid \\U escape '\\U${hex}' in Turtle`);
        }
        out += decodeUnicodeScalarEscape(hex, 'U');
        i += 8;
        break;
      }
      default:
        out += esc;
        break;
    }
  }
  return out;
}

function unescapeLocalName(raw: string): string {
  return raw.replace(/\\([_~.\-!$&'()*+,;=/?#@%])/g, '$1');
}

function isBoundaryChar(ch: string | undefined): boolean {
  return (
    ch === undefined ||
    /\s/.test(ch) ||
    ch === '.' ||
    ch === ';' ||
    ch === ',' ||
    ch === '[' ||
    ch === ']' ||
    ch === '(' ||
    ch === ')' ||
    ch === '<' ||
    ch === '"' ||
    ch === "'" ||
    ch === '#'
  );
}

function tokenizeTurtle(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const len = input.length;

  const skipWsAndComments = (): void => {
    while (i < len) {
      const ch = input[i]!;
      if (/\s/.test(ch)) {
        i++;
      } else if (ch === '#') {
        while (i < len && input[i] !== '\n' && input[i] !== '\r') {
          i++;
        }
      } else {
        break;
      }
    }
  };

  const readIriToken = (): Token => {
    i++; // skip '<'
    let raw = '';
    while (i < len && input[i] !== '>') {
      const ch = input[i]!;
      if (ch === '\n' || ch === '\r') {
        throw new WolinParseError('Unclosed <IRI> in Turtle document');
      }
      raw += ch;
      i++;
    }
    if (input[i] !== '>') {
      throw new WolinParseError('Unterminated <IRI> in Turtle document');
    }
    i++; // skip '>'
    return { kind: 'iri', value: unescapeTurtleString(raw) };
  };

  const readPrefixedToken = (): Token => {
    let raw = '';
    while (i < len) {
      const ch = input[i]!;
      if (ch === '\\' && i + 1 < len) {
        raw += ch + input[i + 1]!;
        i += 2;
        continue;
      }
      if (ch === '.') {
        const next = input[i + 1];
        if (isBoundaryChar(next)) {
          break;
        }
      }
      if (
        /\s/.test(ch) ||
        ch === ';' ||
        ch === ',' ||
        ch === '[' ||
        ch === ']' ||
        ch === '(' ||
        ch === ')' ||
        ch === '<' ||
        ch === '>' ||
        ch === '"' ||
        ch === "'" ||
        ch === '#'
      ) {
        break;
      }
      raw += ch;
      i++;
    }
    const colonIdx = raw.indexOf(':');
    if (colonIdx === -1) {
      return { kind: 'word', value: raw };
    }
    const prefix = raw.slice(0, colonIdx);
    const local = unescapeLocalName(raw.slice(colonIdx + 1));
    if (prefix === '_') {
      return { kind: 'bnode', label: local };
    }
    return { kind: 'pname', prefix, local };
  };

  while (true) {
    skipWsAndComments();
    if (i >= len) break;

    const ch = input[i]!;

    if (ch === ';' || ch === ',' || ch === '[' || ch === ']' || ch === '(' || ch === ')') {
      tokens.push({ kind: 'punct', value: ch });
      i++;
      continue;
    }

    if (ch === '.') {
      const next = input[i + 1];
      if (next === undefined || !/[0-9]/.test(next)) {
        tokens.push({ kind: 'punct', value: '.' });
        i++;
        continue;
      }
    }

    if (ch === '<') {
      tokens.push(readIriToken());
      continue;
    }

    if (ch === '"' || ch === "'") {
      const quote = ch;
      const isLong = input.slice(i, i + 3) === quote.repeat(3);
      const delim = isLong ? quote.repeat(3) : quote;
      i += delim.length;
      let raw = '';
      let closed = false;
      while (i < len) {
        if (input[i] === '\\') {
          if (i + 1 >= len) {
            throw new WolinParseError('Unterminated escape in Turtle string literal');
          }
          raw += input[i]! + input[i + 1]!;
          i += 2;
          continue;
        }
        if (isLong && input.slice(i, i + 3) === delim) {
          // Per W3C Turtle 1.1 STRING_LITERAL_LONG_QUOTE, up to 2 trailing quotes before closing """
          let extraQuotes = 0;
          while (extraQuotes < 2 && input[i + 3 + extraQuotes] === quote) {
            extraQuotes++;
          }
          if (extraQuotes > 0) {
            raw += quote.repeat(extraQuotes);
            i += extraQuotes;
          }
          i += 3;
          closed = true;
          break;
        }
        if (!isLong && input[i] === quote) {
          i += 1;
          closed = true;
          break;
        }
        if (!isLong && (input[i] === '\n' || input[i] === '\r')) {
          throw new WolinParseError('Unescaped newline inside single-quoted Turtle literal');
        }
        raw += input[i]!;
        i++;
      }
      if (!closed) {
        throw new WolinParseError('Unterminated string literal in Turtle document');
      }

      const value = unescapeTurtleString(raw);
      let language: string | undefined;
      let datatypeToken: Token | undefined;

      if (input[i] === '@') {
        i++;
        let lang = '';
        while (i < len && /[a-zA-Z0-9-]/.test(input[i]!)) {
          lang += input[i]!;
          i++;
        }
        if (!lang) {
          throw new WolinParseError('Empty @lang tag on Turtle literal');
        }
        language = lang.toLowerCase();
      } else if (input.slice(i, i + 2) === '^^') {
        i += 2;
        skipWsAndComments();
        if (input[i] === '<') {
          datatypeToken = readIriToken();
        } else {
          datatypeToken = readPrefixedToken();
        }
      }

      tokens.push({ kind: 'literal', value, language, datatypeToken });
      continue;
    }

    if (ch === '@') {
      let directive = '@';
      i++;
      while (i < len && /[a-zA-Z-]/.test(input[i]!)) {
        directive += input[i]!;
        i++;
      }
      tokens.push({ kind: 'word', value: directive });
      continue;
    }

    tokens.push(readPrefixedToken());
  }

  return tokens;
}

function hasExplicitEmptyOriginPath(rawHttpIri: string): boolean {
  const afterScheme = rawHttpIri.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  const authorityAndRest = afterScheme.split(/[?#]/)[0] ?? '';
  return !authorityAndRest.includes('/');
}

function resolveRelativeIri(rawIri: string, baseIri: string): string {
  try {
    if (rawIri === '') {
      const noFragBase = baseIri.split('#')[0] ?? baseIri;
      const docUrl = new URL(noFragBase);
      if (
        (docUrl.protocol === 'https:' || docUrl.protocol === 'http:') &&
        hasExplicitEmptyOriginPath(noFragBase)
      ) {
        return `${docUrl.protocol}//${docUrl.host}${docUrl.search}`;
      }
      return docUrl.toString();
    }

    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawIri)) {
      const absUrl = new URL(rawIri);
      if (
        (absUrl.protocol === 'https:' || absUrl.protocol === 'http:') &&
        hasExplicitEmptyOriginPath(rawIri)
      ) {
        return `${absUrl.protocol}//${absUrl.host}${absUrl.search}${absUrl.hash}`;
      }
      return absUrl.toString();
    }

    return new URL(rawIri, baseIri).toString();
  } catch (err) {
    throw new WolinParseError(`Invalid IRI '${rawIri}' against base '${baseIri}'`, { cause: err });
  }
}

/**
 * Parse a W3C Turtle 1.1 / N-Triples RDF document into normalized `RdfTriple[]`.
 */
export function parseTurtle(turtle: string, baseIri: string): RdfTriple[] {
  let currentBase = baseIri;
  try {
    new URL(currentBase);
  } catch (err) {
    throw new WolinParseError(`Invalid Turtle base IRI '${baseIri}'`, { cause: err });
  }

  const tokens = tokenizeTurtle(turtle);
  const usedBnodeLabels = new Set<string>();
  for (const t of tokens) {
    if (t.kind === 'bnode') {
      usedBnodeLabels.add(t.label);
    } else if (t.kind === 'literal' && t.datatypeToken?.kind === 'bnode') {
      usedBnodeLabels.add(t.datatypeToken.label);
    }
  }

  const prefixes = new Map<string, string>();
  const triples: RdfTriple[] = [];
  let pos = 0;
  let bnodeSeq = 0;

  const peek = (): Token | undefined => tokens[pos];
  const next = (): Token => {
    const tok = tokens[pos];
    if (!tok) {
      throw new WolinParseError('Unexpected end of Turtle document');
    }
    pos++;
    return tok;
  };
  const expectPunct = (expected: '.' | ';' | ',' | '[' | ']' | '(' | ')'): void => {
    const tok = next();
    if (tok.kind !== 'punct' || tok.value !== expected) {
      throw new WolinParseError(`Expected '${expected}' in Turtle document`);
    }
  };

  const freshBlankNode = (): string => {
    let candidate = `b${++bnodeSeq}`;
    while (usedBnodeLabels.has(candidate)) {
      candidate = `b${++bnodeSeq}`;
    }
    usedBnodeLabels.add(candidate);
    return `_:${candidate}`;
  };

  const resolveIriOrPname = (tok: Token): string => {
    if (tok.kind === 'iri') {
      return resolveRelativeIri(tok.value, currentBase);
    }
    if (tok.kind === 'pname') {
      const ns = prefixes.get(tok.prefix);
      if (ns === undefined) {
        throw new WolinParseError(`Undefined Turtle prefix '${tok.prefix}:'`);
      }
      return `${ns}${tok.local}`;
    }
    throw new WolinParseError('Expected IRI or prefixed name in Turtle document');
  };

  type NodeTerm = {
    value: string;
    objectType: 'iri' | 'literal' | 'blank';
    datatype?: string;
    language?: string;
  };

  const parsePredicateObjectList = (subject: string): number => {
    let predicateCount = 0;
    while (true) {
      const nextTok = peek();
      if (
        !nextTok ||
        (nextTok.kind === 'punct' && (nextTok.value === '.' || nextTok.value === ']'))
      ) {
        break;
      }

      const predTok = next();
      const predicate =
        predTok.kind === 'word' && predTok.value === 'a'
          ? RDF_TYPE_IRI
          : resolveIriOrPname(predTok);

      parseObjectList(subject, predicate);
      predicateCount++;

      const sep = peek();
      if (sep?.kind === 'punct' && sep.value === ';') {
        while (peek()?.kind === 'punct' && (peek() as { value: string }).value === ';') {
          next();
        }
        continue;
      }
      break;
    }
    return predicateCount;
  };

  const parseObjectList = (subject: string, predicate: string): void => {
    while (true) {
      const obj = parseObject();
      triples.push({
        subject,
        predicate,
        object: obj.value,
        objectType: obj.objectType,
        datatype: obj.datatype,
        language: obj.language,
      });

      if (peek()?.kind === 'punct' && (peek() as { value: string }).value === ',') {
        next();
        continue;
      }
      break;
    }
  };

  const parseCollection = (): NodeTerm => {
    expectPunct('(');
    const items: NodeTerm[] = [];
    while (peek() && !(peek()!.kind === 'punct' && (peek() as { value: string }).value === ')')) {
      items.push(parseObject());
    }
    expectPunct(')');

    if (items.length === 0) {
      return { value: RDF_NIL_IRI, objectType: 'iri' };
    }

    const head = freshBlankNode();
    let current = head;
    for (let idx = 0; idx < items.length; idx++) {
      const item = items[idx]!;
      triples.push({
        subject: current,
        predicate: RDF_FIRST_IRI,
        object: item.value,
        objectType: item.objectType,
        datatype: item.datatype,
        language: item.language,
      });
      const restNode = idx + 1 < items.length ? freshBlankNode() : RDF_NIL_IRI;
      triples.push({
        subject: current,
        predicate: RDF_REST_IRI,
        object: restNode,
        objectType: idx + 1 < items.length ? 'blank' : 'iri',
      });
      current = restNode;
    }
    return { value: head, objectType: 'blank' };
  };

  const parseObject = (): NodeTerm => {
    const tok = peek();
    if (!tok) {
      throw new WolinParseError('Unexpected end of Turtle document while reading object');
    }

    if (tok.kind === 'punct' && tok.value === '[') {
      next();
      const bnode = freshBlankNode();
      if (!(peek()?.kind === 'punct' && (peek() as { value: string }).value === ']')) {
        parsePredicateObjectList(bnode);
      }
      expectPunct(']');
      return { value: bnode, objectType: 'blank' };
    }

    if (tok.kind === 'punct' && tok.value === '(') {
      return parseCollection();
    }

    next();
    if (tok.kind === 'iri' || tok.kind === 'pname') {
      return { value: resolveIriOrPname(tok), objectType: 'iri' };
    }
    if (tok.kind === 'bnode') {
      return { value: `_:${tok.label}`, objectType: 'blank' };
    }
    if (tok.kind === 'literal') {
      const datatype = tok.language
        ? RDF_LANG_STRING_IRI
        : tok.datatypeToken
          ? resolveIriOrPname(tok.datatypeToken)
          : XSD_STRING_IRI;
      return {
        value: tok.value,
        objectType: 'literal',
        datatype,
        language: tok.language,
      };
    }
    if (tok.kind === 'word') {
      if (tok.value === 'true' || tok.value === 'false') {
        return { value: tok.value, objectType: 'literal', datatype: XSD_BOOLEAN_IRI };
      }
      if (/^[+-]?[0-9]+$/.test(tok.value)) {
        return { value: tok.value, objectType: 'literal', datatype: XSD_INTEGER_IRI };
      }
      if (/^[+-]?[0-9]*\.[0-9]+$/.test(tok.value)) {
        return { value: tok.value, objectType: 'literal', datatype: XSD_DECIMAL_IRI };
      }
      if (/^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)[eE][+-]?[0-9]+$/.test(tok.value)) {
        return { value: tok.value, objectType: 'literal', datatype: XSD_DOUBLE_IRI };
      }
    }

    throw new WolinParseError('Unexpected token in Turtle object position');
  };

  while (pos < tokens.length) {
    const tok = peek()!;

    // @prefix pfx: <iri> .
    if (tok.kind === 'word' && tok.value === '@prefix') {
      next();
      const pfxTok = next();
      if (pfxTok.kind !== 'pname' || pfxTok.local !== '') {
        throw new WolinParseError('Expected prefix label (e.g. `foaf:`) after @prefix');
      }
      const iriTok = next();
      if (iriTok.kind !== 'iri') {
        throw new WolinParseError('Expected <IRI> namespace in @prefix directive');
      }
      expectPunct('.');
      prefixes.set(pfxTok.prefix, resolveRelativeIri(iriTok.value, currentBase));
      continue;
    }

    // SPARQL-style PREFIX pfx: <iri>
    if (tok.kind === 'word' && tok.value.toUpperCase() === 'PREFIX') {
      next();
      const pfxTok = next();
      if (pfxTok.kind !== 'pname' || pfxTok.local !== '') {
        throw new WolinParseError('Expected prefix label after PREFIX');
      }
      const iriTok = next();
      if (iriTok.kind !== 'iri') {
        throw new WolinParseError('Expected <IRI> namespace in PREFIX directive');
      }
      prefixes.set(pfxTok.prefix, resolveRelativeIri(iriTok.value, currentBase));
      continue;
    }

    // @base <iri> .
    if (tok.kind === 'word' && tok.value === '@base') {
      next();
      const iriTok = next();
      if (iriTok.kind !== 'iri') {
        throw new WolinParseError('Expected <IRI> after @base');
      }
      expectPunct('.');
      currentBase = resolveRelativeIri(iriTok.value, currentBase);
      continue;
    }

    // SPARQL-style BASE <iri>
    if (tok.kind === 'word' && tok.value.toUpperCase() === 'BASE') {
      next();
      const iriTok = next();
      if (iriTok.kind !== 'iri') {
        throw new WolinParseError('Expected <IRI> after BASE');
      }
      currentBase = resolveRelativeIri(iriTok.value, currentBase);
      continue;
    }

    // Triples statement: blankNodePropertyList predicateObjectList? '.' | subject predicateObjectList '.'
    if (tok.kind === 'punct' && tok.value === '[') {
      next();
      const subject = freshBlankNode();
      let bnodePredCount = 0;
      if (!(peek()?.kind === 'punct' && (peek() as { value: string }).value === ']')) {
        bnodePredCount = parsePredicateObjectList(subject);
      }
      expectPunct(']');
      if (peek()?.kind === 'punct' && (peek() as { value: string }).value === '.') {
        if (bnodePredCount === 0) {
          throw new WolinParseError('Empty [] subject requires a predicate-object list');
        }
        next();
        continue;
      }
      const trailingCount = parsePredicateObjectList(subject);
      if (bnodePredCount === 0 && trailingCount === 0) {
        throw new WolinParseError('Expected predicate-object list in Turtle statement');
      }
      expectPunct('.');
      continue;
    }

    let subject: string;
    if (tok.kind === 'punct' && tok.value === '(') {
      const col = parseCollection();
      subject = col.value;
    } else {
      const subjTok = next();
      if (subjTok.kind === 'bnode') {
        subject = `_:${subjTok.label}`;
      } else {
        subject = resolveIriOrPname(subjTok);
      }
    }

    const count = parsePredicateObjectList(subject);
    if (count === 0) {
      throw new WolinParseError(`Subject '${subject}' missing predicate-object list in Turtle`);
    }
    expectPunct('.');
  }

  return triples;
}

/**
 * Parse a W3C Solid WebID Profile Turtle document and extract `pim:storage`,
 * `solid:oidcIssuer`, `ldp:inbox`, and profile display name (`foaf:name` / `vcard:fn`).
 */
export function parseWebIdProfile(
  turtle: string,
  webId: string,
  documentIri?: string,
): WebIdProfile {
  const trimmedWebId = webId.trim();
  if (!trimmedWebId) {
    throw new WolinParseError('webId must not be empty');
  }
  const rawDocIri = (documentIri ?? trimmedWebId.split('#')[0] ?? trimmedWebId).trim();
  // Use standard URL form for base document resolution (e.g. `https://alice.wolin.id` -> `https://alice.wolin.id/`)
  let normalizedDocBase: string;
  try {
    const u = new URL(rawDocIri);
    u.hash = '';
    normalizedDocBase = u.toString();
  } catch (err) {
    throw new WolinParseError(`Invalid WebID document IRI '${rawDocIri}'`, { cause: err });
  }

  const canonicalWebId = new URL(trimmedWebId, normalizedDocBase).toString();
  const triples = parseTurtle(turtle, normalizedDocBase);

  const oidcIssuers: string[] = [];
  const storages: string[] = [];
  const inboxes: string[] = [];
  const seenIssuers = new Set<string>();
  const seenStorages = new Set<string>();
  const seenInboxes = new Set<string>();
  let foafName: string | undefined;
  let vcardFn: string | undefined;

  for (const triple of triples) {
    const canonicalSubject = triple.subject.startsWith('_:')
      ? triple.subject
      : (() => {
          try {
            return new URL(triple.subject).toString();
          } catch {
            return triple.subject;
          }
        })();

    if (triple.subject !== canonicalWebId && canonicalSubject !== canonicalWebId) {
      continue;
    }

    if (triple.objectType === 'iri') {
      if (triple.predicate === SOLID_OIDC_ISSUER_IRI && !seenIssuers.has(triple.object)) {
        seenIssuers.add(triple.object);
        oidcIssuers.push(triple.object);
      } else if (triple.predicate === PIM_STORAGE_IRI && !seenStorages.has(triple.object)) {
        seenStorages.add(triple.object);
        storages.push(triple.object);
      } else if (triple.predicate === LDP_INBOX_IRI && !seenInboxes.has(triple.object)) {
        seenInboxes.add(triple.object);
        inboxes.push(triple.object);
      }
    } else if (triple.objectType === 'literal') {
      if (triple.predicate === FOAF_NAME_IRI && foafName === undefined) {
        foafName = triple.object;
      } else if (triple.predicate === VCARD_FN_IRI && vcardFn === undefined) {
        vcardFn = triple.object;
      }
    }
  }

  return {
    webId: canonicalWebId,
    oidcIssuers,
    storages,
    inboxes,
    name: foafName ?? vcardFn,
    primaryStorage: storages[0],
    primaryOidcIssuer: oidcIssuers[0],
    primaryInbox: inboxes[0],
    triples,
  };
}

/**
 * Verify the W3C Solid-OIDC trust chain: `<webId> solid:oidcIssuer <expectedIssuer>`.
 */
export function verifyWebIdOidcIssuer(profile: WebIdProfile, expectedIssuer: string): void {
  const trimmed = expectedIssuer.trim().replace(/\/+$/, '');
  if (!trimmed) {
    throw new WolinAuthError('Expected Solid-OIDC issuer must not be empty');
  }
  const matched = profile.oidcIssuers.some((iss) => iss.trim().replace(/\/+$/, '') === trimmed);
  if (!matched) {
    throw new WolinAuthError(
      `Solid-OIDC trust chain verification failed: WebID '${profile.webId}' does not authorize oidcIssuer '${expectedIssuer}'`,
    );
  }
}

/**
 * Dereference an HTTP(S) WebID URI (e.g. `https://alice.wolin.id/profile/card#me`)
 * and parse its Solid WebID Profile Turtle document.
 */
export async function fetchWebIdProfile(
  webId: string,
  options?: { fetchFn?: typeof fetch },
): Promise<WebIdProfile> {
  const trimmed = webId.trim();
  if (!trimmed || trimmed.length > 2048 || /[\s\x00-\x1f\x7f\\]/.test(trimmed)) {
    throw new WolinAuthError('WebID URI is empty, oversized, or contains invalid characters');
  }
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(trimmed);
  } catch (err) {
    throw new WolinAuthError(`Malformed WebID URI '${webId}'`, { cause: err });
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    throw new WolinAuthError(
      `WebID URI requires http or https scheme (got '${parsedUrl.protocol}')`,
    );
  }
  if (parsedUrl.username !== '' || parsedUrl.password !== '') {
    throw new WolinAuthError('Userinfo credentials are forbidden in WebID URIs');
  }
  if (parsedUrl.search !== '') {
    throw new WolinAuthError('Query strings are forbidden in Solid WebID Profile URIs');
  }

  parsedUrl.hash = '';
  const documentIri = parsedUrl.toString();
  const customFetch = options?.fetchFn;
  const fetchImpl: typeof fetch = customFetch
    ? (input, init) => customFetch(input, init)
    : (input, init) => globalThis.fetch(input, init);

  const response = await fetchImpl(documentIri, {
    method: 'GET',
    headers: {
      Accept: 'text/turtle, application/n-triples;q=0.8',
    },
  });

  if (!response.ok) {
    throw new WolinAuthError(
      `Failed to dereference WebID Profile '${documentIri}': HTTP ${response.status}`,
    );
  }

  const rawContentType = response.headers.get('Content-Type');
  if (rawContentType !== null) {
    const mediaType = rawContentType.split(';')[0]?.trim().toLowerCase() ?? '';
    if (!SUPPORTED_TURTLE_MEDIA_TYPES.has(mediaType)) {
      throw new WolinParseError(
        `Unsupported WebID Profile Content-Type '${mediaType}' (expected text/turtle or application/n-triples)`,
      );
    }
  }

  let effectiveDocIri = documentIri;
  if (response.url) {
    let redirectedUrl: URL;
    try {
      redirectedUrl = new URL(response.url);
    } catch (err) {
      throw new WolinAuthError(`Malformed redirect URL '${response.url}' during WebID dereference`, {
        cause: err,
      });
    }
    if (redirectedUrl.protocol !== 'https:' && redirectedUrl.protocol !== 'http:') {
      throw new WolinAuthError(
        `Disallowed redirect scheme '${redirectedUrl.protocol}' during WebID dereference`,
      );
    }
    if (parsedUrl.protocol === 'https:' && redirectedUrl.protocol !== 'https:') {
      throw new WolinAuthError(
        'HTTPS WebID dereferencing must not downgrade to cleartext HTTP via redirect',
      );
    }
    if (redirectedUrl.username !== '' || redirectedUrl.password !== '') {
      throw new WolinAuthError('Userinfo credentials are forbidden in redirected WebID URL');
    }
    redirectedUrl.hash = '';
    effectiveDocIri = redirectedUrl.toString();
  }

  const turtle = await response.text();
  return parseWebIdProfile(turtle, trimmed, effectiveDocIri);
}

/**
 * Extract sorted `ldp:contains` child IRIs from a Solid LDP Container Turtle document.
 */
export function parseContainerTurtle(turtle: string, containerIri: string): string[] {
  const canonicalContainer = new URL(containerIri).toString();
  const triples = parseTurtle(turtle, canonicalContainer);
  const children = new Set<string>();

  for (const triple of triples) {
    if (
      triple.subject === canonicalContainer &&
      triple.predicate === LDP_CONTAINS_IRI &&
      triple.objectType === 'iri'
    ) {
      children.add(triple.object);
    }
  }

  return Array.from(children).sort();
}
