/*
 * Who may open which path of an app behind a proxy (specs/122 FR-005–FR-012, research R8).
 *
 * One function decides for both the live check and the console's access check, so the two can never disagree
 * about the same person, request and rules (FR-011). It is bundled into the console, which is why it imports
 * nothing: no `node:*`, no settings, no adapters.
 */

export type Who =
	| { kind: 'groups'; groupIds: string[] }
	| { kind: 'project' }
	| { kind: 'public'; subtree: boolean }
	| { kind: 'none' };

export interface PathRule {
	path: string;
	who: Who;
}

/* A person as the decision needs them: whether the project lets them sign in, and their groups now. */
export interface Person {
	canSignIn: boolean;
	groupIds: readonly string[];
}

export type Outcome = 'allow' | 'sign_in' | 'deny';

export type Reason =
	| 'allowed'
	| 'public'
	| 'no_session'
	| 'not_in_group'
	| 'cannot_sign_in'
	| 'rule_no_one'
	| 'ambiguous_path'
	| 'missing_forwarded'
	| 'not_found'
	| 'unsafe_value'
	| 'rate_limited';

export interface Decision {
	outcome: Outcome;
	reason: Reason;
	/* The path of the rule that decided, or null when none did. */
	rule: string | null;
	/* The path as it was understood, or null when it could not be. */
	path: string | null;
}

export type Ambiguity =
	| 'not_absolute'
	| 'control_character'
	| 'encoded_separator'
	| 'backslash'
	| 'semicolon'
	| 'bad_escape'
	| 'slash_and_dot_segments';

export type CanonicalPath = { path: string } | { ambiguous: Ambiguity };

const UNRESERVED = /[A-Za-z0-9\-._~]/;

/*
 * The path a request is decided by.
 *
 * Ambiguity is looked for in the raw path before anything is decoded: decoding `%2E` first would turn it into a dot
 * segment that resolves away instead of a refusal, and an encoded slash or backslash is read as a separator by some
 * applications and not by others. Whatever the app behind the proxy might read differently from this function is
 * refused rather than guessed at (FR-009).
 */
export function canonicalPath(raw: string): CanonicalPath {
	if (hasControlCharacter(raw)) return { ambiguous: 'control_character' };
	const end = raw.search(/[?#]/);
	const path = end === -1 ? raw : raw.slice(0, end);
	if (!path.startsWith('/')) return { ambiguous: 'not_absolute' };
	if (path.includes('\\')) return { ambiguous: 'backslash' };
	if (path.includes(';')) return { ambiguous: 'semicolon' };
	if (/%(2f|5c|2e)/i.test(path)) return { ambiguous: 'encoded_separator' };
	if (/%(0[0-9a-f]|1[0-9a-f]|7f)/i.test(path)) {
		return { ambiguous: 'control_character' };
	}

	const decoded = decodeUnreserved(path);
	if (decoded === null) return { ambiguous: 'bad_escape' };

	/*
	 * Applications disagree on whether `//` collapses before or after `..` is resolved (`/admin//..` is `/admin/`
	 * one way and `/` the other). Where the order changes the answer, the path is refused, so no app can be
	 * reached at a path this function placed under a different rule.
	 */
	const dotsFirst = collapseSlashes(removeDotSegments(decoded));
	const slashesFirst = removeDotSegments(collapseSlashes(decoded));
	if (dotsFirst !== slashesFirst) {
		return { ambiguous: 'slash_and_dot_segments' };
	}
	return { path: withoutTrailingSlash(dotsFirst) };
}

/* A C0 control character or DEL: what would end or split a header line, and what no path may carry. */
export function hasControlCharacter(value: string): boolean {
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		if (code < 0x20 || code === 0x7f) return true;
	}
	return false;
}

/* Decodes only escapes of unreserved characters; every other escape stays as it is. Null for a broken escape. */
function decodeUnreserved(path: string): string | null {
	let out = '';
	for (let i = 0; i < path.length; i++) {
		const char = path[i];
		if (char !== '%') {
			out += char;
			continue;
		}
		const hex = path.slice(i + 1, i + 3);
		if (!/^[0-9a-fA-F]{2}$/.test(hex)) return null;
		const decoded = String.fromCharCode(parseInt(hex, 16));
		out += UNRESERVED.test(decoded) ? decoded : `%${hex.toUpperCase()}`;
		i += 2;
	}
	return out;
}

/* RFC 3986 §5.2.4. */
function removeDotSegments(path: string): string {
	let input = path;
	let output = '';
	while (input.length > 0) {
		if (input.startsWith('../')) input = input.slice(3);
		else if (input.startsWith('./')) input = input.slice(2);
		else if (input.startsWith('/./')) input = input.slice(2);
		else if (input === '/.') input = '/';
		else if (input.startsWith('/../')) {
			input = input.slice(3);
			output = output.slice(0, Math.max(output.lastIndexOf('/'), 0));
		} else if (input === '/..') {
			input = '/';
			output = output.slice(0, Math.max(output.lastIndexOf('/'), 0));
		} else if (input === '.' || input === '..') input = '';
		else {
			const next = input.indexOf('/', 1);
			const segment = next === -1 ? input : input.slice(0, next);
			output += segment;
			input = input.slice(segment.length);
		}
	}
	return output;
}

function collapseSlashes(path: string): string {
	return path.replace(/\/{2,}/g, '/');
}

function withoutTrailingSlash(path: string): string {
	if (path === '') return '/';
	return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

function segmentsOf(path: string): number {
	return path === '/' ? 0 : path.split('/').length - 1;
}

/* Whether `rulePath` is `path` or a whole-segment prefix of it. */
function covers(rulePath: string, path: string, exactCase: boolean): boolean {
	const rule = exactCase ? rulePath : rulePath.toLowerCase();
	const target = exactCase ? path : path.toLowerCase();
	if (rule === '/') return true;
	return target === rule || target.startsWith(`${rule}/`);
}

function isReadMethod(method: string): boolean {
	const upper = method.toUpperCase();
	return upper === 'GET' || upper === 'HEAD';
}

/*
 * The rule that decides `path` (already canonical) for `method`: the longest whole-segment match, without regard to
 * letter case (FR-007). A public rule decides only with its exact letter case, only GET and HEAD, and only its
 * exact path unless it covers its subtree (FR-008); where it does not, the next-longest rule decides — so a mistake
 * in a public rule falls on the closed side. Rule order never matters. Null when no rule decides, which can only
 * happen when the root rule itself is public and does not cover this request.
 */
export function ruleFor(
	rules: readonly PathRule[],
	path: string,
	method: string
): PathRule | null {
	const candidates = rules
		.map((rule) => ({ ...rule, path: withoutTrailingSlash(rule.path) }))
		.filter((rule) => covers(rule.path, path, false))
		.sort(
			(a, b) =>
				segmentsOf(b.path) - segmentsOf(a.path) ||
				/* Two rules on one path in different letter case: the closed one first. */
				Number(a.who.kind === 'public') - Number(b.who.kind === 'public')
		);
	for (const rule of candidates) {
		if (rule.who.kind !== 'public') return rule;
		if (!isReadMethod(method)) continue;
		if (!covers(rule.path, path, true)) continue;
		if (path === rule.path || rule.who.subtree) return rule;
	}
	return null;
}

export interface DecideInput {
	rules: readonly PathRule[];
	method: string;
	rawPath: string;
	/* Null when the request carries no usable session. */
	person: Person | null;
}

export function decide({
	rules,
	method,
	rawPath,
	person
}: DecideInput): Decision {
	const canonical = canonicalPath(rawPath);
	if ('ambiguous' in canonical) {
		return {
			outcome: 'deny',
			reason: 'ambiguous_path',
			rule: null,
			path: null
		};
	}
	const { path } = canonical;
	const rule = ruleFor(rules, path, method);
	if (!rule) {
		return { outcome: 'deny', reason: 'rule_no_one', rule: null, path };
	}
	const decided = (outcome: Outcome, reason: Reason): Decision => ({
		outcome,
		reason,
		rule: rule.path,
		path
	});
	const { who } = rule;
	if (who.kind === 'public') return decided('allow', 'public');
	if (who.kind === 'none') return decided('deny', 'rule_no_one');
	if (!person) return decided('sign_in', 'no_session');
	if (!person.canSignIn) return decided('deny', 'cannot_sign_in');
	if (who.kind === 'project') return decided('allow', 'allowed');
	const admitted = who.groupIds.some((id) => person.groupIds.includes(id));
	return admitted
		? decided('allow', 'allowed')
		: decided('deny', 'not_in_group');
}

export interface Widening {
	/* A rule's path, or `<path>/*` for everything under it that no more specific rule decides. */
	path: string;
	from: Who | null;
	to: Who | null;
}

/* Whether `to` admits someone `from` did not. A rule-less request is denied, so it admits no one. */
function widens(from: Who | null, to: Who | null): boolean {
	if (!to || to.kind === 'none') return false;
	if (!from || from.kind === 'none') {
		return to.kind !== 'groups' || to.groupIds.length > 0;
	}
	if (to.kind === 'public') return from.kind !== 'public';
	if (to.kind === 'project') return from.kind === 'groups';
	if (from.kind !== 'groups') return false;
	return to.groupIds.some((id) => !from.groupIds.includes(id));
}

const PROBE_METHODS = ['GET', 'POST'] as const;

/*
 * Where a change of rules lets more people in (FR-036), judged by the access that results rather than by which rows
 * changed: every path named by either rule set, and everything beneath each, is decided under both, so removing a
 * rule shows up as its path handed to its parent. A write method is probed as well as a read one, because a public
 * rule covers only reads and hands writes to its parent.
 */
export function widenings(
	before: readonly PathRule[],
	after: readonly PathRule[]
): Widening[] {
	const paths = [
		...new Set(
			[...before, ...after].map((rule) => withoutTrailingSlash(rule.path))
		)
	].sort((a, b) => segmentsOf(a) - segmentsOf(b));
	const found: Widening[] = [];
	for (const path of paths) {
		for (const probe of [path, path === '/' ? '/*' : `${path}/*`]) {
			const change = wideningAt(before, after, probe);
			/* The same change already listed for a path above this one says it for this one too. */
			const listed = found.some(
				(w) =>
					sameWho(w.from, change?.from ?? null) &&
					sameWho(w.to, change?.to ?? null) &&
					covers(baseOf(w.path), baseOf(probe), true)
			);
			if (change && !listed) found.push({ path: probe, ...change });
		}
	}
	return found;
}

function baseOf(probe: string): string {
	return probe.endsWith('/*') ? probe.slice(0, -2) || '/' : probe;
}

function wideningAt(
	before: readonly PathRule[],
	after: readonly PathRule[],
	path: string
): { from: Who | null; to: Who | null } | null {
	for (const method of PROBE_METHODS) {
		const from = ruleFor(before, path, method)?.who ?? null;
		const to = ruleFor(after, path, method)?.who ?? null;
		if (widens(from, to)) return { from, to };
	}
	return null;
}

function sameWho(a: Who | null, b: Who | null): boolean {
	return JSON.stringify(a) === JSON.stringify(b);
}
