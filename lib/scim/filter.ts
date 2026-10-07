import type { BucketGroupFilter, EndUserFilter } from '../adapters/types.js';
import {
	FORBIDDEN_KEYS,
	SCIM_GROUP_SCHEMA,
	SCIM_MAX_FILTER_LENGTH,
	SCIM_USER_SCHEMA
} from '../consts/scim.js';
import { ScimError } from './errors.js';

/*
 * The SCIM filters this server answers, and nothing else (specs/070 FR-032, research R10).
 *
 * Our own parser rather than `scim2-parse-filter`, which issue #62 named: its 0.3.0 quoted-string regex
 * backtracks exponentially on an unterminated string of newlines — reachable from `?filter=` — and it
 * overflows the stack on deep nesting. Both target clients send only `eq` and `and`, so the grammar here is
 * tiny, the tokenizer is a single linear pass, and the input is capped before it starts.
 *
 * Accepted, alone or joined by `and` (keywords and attribute names in any letter case, core attribute names
 * optionally qualified by the User schema URN):
 *
 *   userName eq "…"     externalId eq "…"     id eq "…"
 *   emails eq "…"       emails.value eq "…"   emails[value eq "…"]
 *   emails[type eq "…" and value eq "…"]      emails[type eq "…"].value eq "…"
 *
 * Everything else is 400 `invalidFilter`. The output is the store's fixed equality lookup with
 * `provisionedBy` set: no part of the parsed expression but a literal value reaches a query (FR-033).
 */

type Token =
	| { kind: 'word'; text: string }
	| { kind: 'string'; text: string }
	| { kind: 'punct'; text: '[' | ']' | '(' | ')' };

export function invalidFilter(detail: string): ScimError {
	return new ScimError(400, 'invalidFilter', detail);
}

const WORD = /[A-Za-z0-9:._$-]/;

/* One pass, no backtracking: every character is consumed exactly once. */
export function tokenize(
	input: string,
	fail: (detail: string) => ScimError = invalidFilter
): Token[] {
	const tokens: Token[] = [];
	let i = 0;
	while (i < input.length) {
		const c = input[i];
		if (c === ' ' || c === '\t') {
			i++;
			continue;
		}
		if (c === '[' || c === ']' || c === '(' || c === ')') {
			tokens.push({ kind: 'punct', text: c });
			i++;
			continue;
		}
		if (c === '"') {
			let text = '';
			i++;
			let closed = false;
			while (i < input.length) {
				const d = input[i];
				if (d === '\\') {
					const next = input[i + 1];
					if (next === undefined) break;
					text += next === 'n' ? '\n' : next === 't' ? '\t' : next;
					i += 2;
					continue;
				}
				if (d === '"') {
					closed = true;
					i++;
					break;
				}
				text += d;
				i++;
			}
			if (!closed) throw fail('a quoted value is not closed');
			tokens.push({ kind: 'string', text });
			continue;
		}
		if (WORD.test(c)) {
			let text = '';
			while (i < input.length && WORD.test(input[i])) {
				text += input[i];
				i++;
			}
			tokens.push({ kind: 'word', text });
			continue;
		}
		throw fail('the filter contains a character it cannot hold');
	}
	return tokens;
}

const CORE_PREFIX = `${SCIM_USER_SCHEMA}:`.toLowerCase();

/* A core attribute path, lower-cased, with any User-schema URN qualifier removed. */
export function coreName(path: string): string {
	const lower = path.toLowerCase();
	return lower.startsWith(CORE_PREFIX)
		? lower.slice(CORE_PREFIX.length)
		: lower;
}

function isKeyword(token: Token | undefined, keyword: string): boolean {
	return token?.kind === 'word' && token.text.toLowerCase() === keyword;
}

export interface ParsedUserFilter {
	filter: EndUserFilter;
	/* The `type` an email filter also requires, checked against the stored profile entry. */
	emailType?: string;
	/* Two different values for one field: the conjunction matches nobody. */
	impossible: boolean;
}

class Cursor {
	private at = 0;
	constructor(private readonly tokens: Token[]) {}
	peek(): Token | undefined {
		return this.tokens[this.at];
	}
	next(): Token | undefined {
		return this.tokens[this.at++];
	}
	done(): boolean {
		return this.at >= this.tokens.length;
	}
}

function expectEq(cursor: Cursor) {
	if (!isKeyword(cursor.next(), 'eq')) {
		throw invalidFilter('only the eq operator is supported');
	}
}

function expectString(cursor: Cursor): string {
	const token = cursor.next();
	if (token?.kind !== 'string') {
		throw invalidFilter('a comparison value must be a quoted string');
	}
	return token.text;
}

/* `type eq "…" and value eq "…"` in either order, or `value eq "…"`, inside `emails[…]`. */
function emailValueFilter(cursor: Cursor): { value?: string; type?: string } {
	const result: { value?: string; type?: string } = {};
	for (;;) {
		const attr = cursor.next();
		if (attr?.kind !== 'word') throw invalidFilter('unsupported filter');
		const name = attr.text.toLowerCase();
		if (name !== 'value' && name !== 'type') {
			throw invalidFilter(
				'only value and type can be filtered inside emails[…]'
			);
		}
		expectEq(cursor);
		const value = expectString(cursor);
		if (result[name] !== undefined && result[name] !== value) {
			throw invalidFilter('a value filter names one attribute twice');
		}
		result[name] = value;
		if (isKeyword(cursor.peek(), 'and')) {
			cursor.next();
			continue;
		}
		return result;
	}
}

interface Term {
	field: 'userName' | 'externalId' | 'id' | 'email';
	value: string;
	emailType?: string;
}

function term(cursor: Cursor): Term {
	const attr = cursor.next();
	if (attr?.kind !== 'word') throw invalidFilter('unsupported filter');
	if (
		FORBIDDEN_KEYS.some((k) =>
			attr.text.toLowerCase().includes(k.toLowerCase())
		)
	) {
		throw invalidFilter('unsupported filter');
	}
	const name = coreName(attr.text);

	if (name === 'emails' && cursor.peek()?.kind === 'punct') {
		const open = cursor.next();
		if (open?.text !== '[') throw invalidFilter('unsupported filter');
		const inner = emailValueFilter(cursor);
		if (cursor.next()?.text !== ']') {
			throw invalidFilter('a value filter is not closed');
		}
		/* `emails[type eq "work"].value eq "…"` — the trailing sub-attribute arrives glued as `.value`. */
		const after = cursor.peek();
		if (after?.kind === 'word' && after.text.toLowerCase() === '.value') {
			cursor.next();
			if (inner.value !== undefined) {
				throw invalidFilter('the email value is given twice');
			}
			expectEq(cursor);
			return {
				field: 'email',
				value: expectString(cursor),
				emailType: inner.type
			};
		}
		if (inner.value === undefined) {
			throw invalidFilter('an emails[…] filter must name the address');
		}
		return { field: 'email', value: inner.value, emailType: inner.type };
	}

	expectEq(cursor);
	const value = expectString(cursor);
	switch (name) {
		case 'username':
			return { field: 'userName', value };
		case 'externalid':
			return { field: 'externalId', value };
		case 'id':
			return { field: 'id', value };
		case 'emails':
		case 'emails.value':
			return { field: 'email', value };
		default:
			throw invalidFilter(`filtering on ${attr.text} is not supported`);
	}
}

export function parseUserFilter(
	input: string,
	connectionId: string
): ParsedUserFilter {
	if (input.length > SCIM_MAX_FILTER_LENGTH) {
		throw invalidFilter('the filter is too long');
	}
	const cursor = new Cursor(tokenize(input));
	if (cursor.done()) throw invalidFilter('the filter is empty');

	const filter: EndUserFilter = { provisionedBy: connectionId };
	let emailType: string | undefined;
	let impossible = false;
	for (;;) {
		const { field, value, emailType: type } = term(cursor);
		const existing = filter[field];
		if (existing !== undefined && existing !== value) impossible = true;
		filter[field] = value;
		if (type !== undefined) {
			if (emailType !== undefined && emailType !== type) impossible = true;
			emailType = type;
		}
		if (cursor.done()) break;
		if (!isKeyword(cursor.next(), 'and')) {
			throw invalidFilter('terms may only be joined by and');
		}
	}
	return { filter, emailType, impossible };
}

const GROUP_PREFIX = `${SCIM_GROUP_SCHEMA}:`.toLowerCase();

/* What a `/Groups` filter asks the store for. `provisionedBy` is always the requesting connection's. */
export interface ParsedGroupFilter {
	filter: Omit<BucketGroupFilter, 'bucketId'> & { provisionedBy: string };
	impossible: boolean;
}

type GroupField = 'displayName' | 'externalId' | 'id' | 'member';

/*
 * One `/Groups` term: `displayName eq`, `externalId eq`, `id eq`, `members[value eq "…"]` or
 * `members.value eq "…"` — what IPSIE AL SCIM §6.2.5 requires and what Entra's membership check
 * (`id eq "…" and members[value eq "…"]`) sends. Everything else is `invalidFilter`.
 */
function groupTerm(cursor: Cursor): { field: GroupField; value: string } {
	const attr = cursor.next();
	if (attr?.kind !== 'word') throw invalidFilter('unsupported filter');
	if (
		FORBIDDEN_KEYS.some((k) =>
			attr.text.toLowerCase().includes(k.toLowerCase())
		)
	) {
		throw invalidFilter('unsupported filter');
	}
	const lower = attr.text.toLowerCase();
	const name = lower.startsWith(GROUP_PREFIX)
		? lower.slice(GROUP_PREFIX.length)
		: lower;

	if (name === 'members' && cursor.peek()?.kind === 'punct') {
		if (cursor.next()?.text !== '[') throw invalidFilter('unsupported filter');
		const inner = cursor.next();
		if (inner?.kind !== 'word' || inner.text.toLowerCase() !== 'value') {
			throw invalidFilter('only value can be filtered inside members[…]');
		}
		expectEq(cursor);
		const value = expectString(cursor);
		if (cursor.next()?.text !== ']') {
			throw invalidFilter('a value filter is not closed');
		}
		return { field: 'member', value };
	}

	expectEq(cursor);
	const value = expectString(cursor);
	switch (name) {
		case 'displayname':
			return { field: 'displayName', value };
		case 'externalid':
			return { field: 'externalId', value };
		case 'id':
			return { field: 'id', value };
		case 'members.value':
			return { field: 'member', value };
		default:
			throw invalidFilter(`filtering on ${attr.text} is not supported`);
	}
}

export function parseGroupFilter(
	input: string,
	connectionId: string
): ParsedGroupFilter {
	if (input.length > SCIM_MAX_FILTER_LENGTH) {
		throw invalidFilter('the filter is too long');
	}
	const cursor = new Cursor(tokenize(input));
	if (cursor.done()) throw invalidFilter('the filter is empty');

	const filter: ParsedGroupFilter['filter'] = { provisionedBy: connectionId };
	let impossible = false;
	for (;;) {
		const { field, value } = groupTerm(cursor);
		const existing = filter[field];
		/* `displayName` is compared case-insensitively, so two spellings of one name are not a conflict. */
		const same =
			field === 'displayName'
				? existing?.toLowerCase() === value.toLowerCase()
				: existing === value;
		if (existing !== undefined && !same) impossible = true;
		filter[field] = value;
		if (cursor.done()) break;
		if (!isKeyword(cursor.next(), 'and')) {
			throw invalidFilter('terms may only be joined by and');
		}
	}
	return { filter, impossible };
}
