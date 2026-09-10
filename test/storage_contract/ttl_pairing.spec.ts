import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { STORAGE_INVENTORY } from 'lib/consts/storage_inventory.js';

/*
 * The ttl pairing invariant:
 *
 *   an area declared `reaped` receives a ttl on every upsert;
 *   an area declared `reaped: null` never receives one.
 *
 * Why it is worth a guard. The two production backends differ in what an upsert with no ttl does to
 * a stored expiry: PostgreSQL's natural `ON CONFLICT DO UPDATE` clears the column, MongoDB's `$set`
 * leaves a stale value behind. That difference is *declared rather than converged* (research D9), and
 * the entire justification for declaring it is that this invariant makes it unobservable — a reaped
 * area always writes a fresh expiry, and the one area upserted without a ttl has no expiry index for
 * a stale value to feed.
 *
 * So this file is not a test of behaviour. It is the thing that keeps a written-down divergence true.
 * If it fails, the divergence stops being unobservable and the register entry stops being honest.
 *
 * It passes on first run — the property already holds. That is the point: it is drift protection, and
 * the PostgreSQL work is exactly the kind of change that would break it.
 *
 * Everything here is derived from source rather than declared in a list. A hand-maintained table of
 * call sites would be forgotten by precisely the author who forgot the invariant.
 */

const LIB = resolve(import.meta.dir, '../../lib');

function libSources(): string[] {
	return (
		readdirSync(LIB, { recursive: true, encoding: 'utf8' })
			.filter((entry) => entry.endsWith('.ts'))
			.map((entry) => join(LIB, entry))
			/* The adapters implement upsert; they do not call it with a ttl decision to get wrong. */
			.filter(
				(file) =>
					!relative(LIB, file).replaceAll('\\', '/').startsWith('adapters/')
			)
	);
}

const reapedByArea = new Map(
	STORAGE_INVENTORY.map((area) => [area.name, area.reaped !== null])
);

/*
 * The module-local helpers that wrap one area — `function records() { return adapter('FederationState'); }`
 * and its seven siblings. Resolving them is what lets the sweep see `records().upsert(...)` as an
 * upsert against FederationState instead of an unrecognised receiver.
 */
function helperAreas(source: string): Map<string, string> {
	const helpers = new Map<string, string>();
	const pattern =
		/function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{\s*return\s+adapter\(\s*'([^']+)'\s*\)\s*;?\s*\}/g;
	for (const match of source.matchAll(pattern)) {
		const [, name, area] = match;
		if (name && area) helpers.set(name, area);
	}
	return helpers;
}

/*
 * How many arguments the call starting at `open` takes, by walking the text and matching brackets.
 *
 * A regex cannot do this: every one of these calls passes an object literal, most span several lines,
 * and some contain a nested call or a spread. Counting top-level commas between balanced delimiters
 * is the only way to tell `upsert(id, payload)` from `upsert(id, payload, ttl)` reliably — and that
 * distinction is the whole subject of this file.
 */
function argumentCount(source: string, open: number): number {
	let depth = 0;
	let args = 0;
	let seenContent = false;
	let quote: string | null = null;

	for (let i = open; i < source.length; i++) {
		/* charAt rather than an index: it is typed as string, so the loop needs no assertion to
		 * satisfy a bound the condition already guarantees. */
		const char = source.charAt(i);

		if (quote) {
			if (char === '\\') i++;
			else if (char === quote) quote = null;
			continue;
		}
		if (char === "'" || char === '"' || char === '`') {
			quote = char;
			seenContent = true;
			continue;
		}
		if ('([{'.includes(char)) {
			depth++;
			if (depth > 1) seenContent = true;
			continue;
		}
		if (')]}'.includes(char)) {
			depth--;
			if (depth === 0) return seenContent ? args + 1 : 0;
			continue;
		}
		if (char === ',' && depth === 1) {
			args++;
			continue;
		}
		if (!/\s/.test(char)) seenContent = true;
	}

	throw new Error('unbalanced call expression');
}

/*
 * The receiver of an `.upsert(` call, in the three shapes this codebase uses: a literal
 * `adapter('Area')`, a module-local no-argument helper wrapping one, or a dotted property chain
 * (`Client.adapter`, `this.adapter`).
 *
 * Enumerating the shapes rather than matching "anything up to `.upsert(`" is what keeps the leading
 * `await` — and, in one file, a preceding comment that happened to end in a full stop — out of the
 * captured receiver.
 */
const RECEIVER =
	/(adapter\(\s*'[^']+'\s*\)|[A-Za-z_$][\w$]*\(\s*\)|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.upsert\(/g;

interface CallSite {
	readonly file: string;
	readonly area: string;
	readonly passesTtl: boolean;
}

/*
 * Every direct upsert in lib/, with the area it targets and whether it passes a ttl.
 *
 * A receiver this cannot resolve is a failure, never a skip. That is the drift protection: a new way
 * of reaching an adapter has to be taught to this function deliberately, rather than quietly falling
 * outside the invariant.
 */
function upsertCallSites(): { sites: CallSite[]; unresolved: string[] } {
	const sites: CallSite[] = [];
	const unresolved: string[] = [];

	for (const file of libSources()) {
		const source = readFileSync(file, 'utf8');
		const helpers = helperAreas(source);
		const shown = relative(LIB, file).replaceAll('\\', '/');

		for (const match of source.matchAll(RECEIVER)) {
			const captured = match[1];
			if (captured === undefined || match.index === undefined) continue;

			const receiver = captured.trim();
			const open = match.index + match[0].length - 1;
			const passesTtl = argumentCount(source, open) >= 3;

			const helper = /^([A-Za-z_$][\w$]*)\(\s*\)$/.exec(receiver);
			const literal = /^adapter\(\s*'([^']+)'\s*\)$/.exec(receiver);
			const viaHelper = helper?.[1] ? helpers.get(helper[1]) : undefined;

			if (literal?.[1]) {
				sites.push({ file: shown, area: literal[1], passesTtl });
			} else if (viaHelper !== undefined) {
				sites.push({ file: shown, area: viaHelper, passesTtl });
			} else if (receiver === 'Client.adapter') {
				sites.push({ file: shown, area: 'Client', passesTtl });
			} else if (receiver === 'this.adapter') {
				/* The generic model path, checked on its own below: its area is whatever model is
				 * saving, so it cannot be resolved here and must hold for every reaped area at once. */
				sites.push({ file: shown, area: '*', passesTtl });
			} else {
				unresolved.push(`${shown}: ${receiver}.upsert(...)`);
			}
		}
	}

	return { sites, unresolved };
}

describe('ttl pairing', () => {
	const { sites, unresolved } = upsertCallSites();

	it('resolves the area behind every upsert in lib/', () => {
		expect(unresolved).toEqual([]);
	});

	it('finds the call sites it claims to, so it cannot pass vacuously', () => {
		// A refactor that renamed the method, or a sweep that silently matched nothing, would otherwise
		// read as a clean bill of health.
		expect(sites.length).toBeGreaterThan(10);
	});

	it('passes a ttl on every upsert into an area that is reaped', () => {
		const missing = sites
			.filter((site) => site.area !== '*')
			.filter((site) => reapedByArea.get(site.area) === true && !site.passesTtl)
			.map((site) => `${site.file} -> ${site.area}`);

		// A reaped area whose record is written without a ttl is where a stale expiry becomes reachable
		// on MongoDB, and where the two backends stop agreeing.
		expect(missing).toEqual([]);
	});

	it('passes no ttl on any upsert into an area that is permanent', () => {
		const spurious = sites
			.filter((site) => site.area !== '*')
			.filter((site) => reapedByArea.get(site.area) === false && site.passesTtl)
			.map((site) => `${site.file} -> ${site.area}`);

		// The inverse half, and the more dangerous one. A ttl written into an area with no expiry index
		// leaves a field nothing reaps today — inert until somebody adds the index, and then it silently
		// deletes records that were never meant to expire. The inventory says exactly this at `Client`.
		expect(spurious).toEqual([]);
	});

	it('names an area the inventory declares, at every call site', () => {
		const unknown = sites
			.filter((site) => site.area !== '*')
			.filter((site) => !reapedByArea.has(site.area))
			.map((site) => `${site.file} -> ${site.area}`);

		expect(unknown).toEqual([]);
	});

	it('always passes a ttl on the generic model save path', () => {
		// Every reaped model area is written through BaseModel.save, so this single call site carries
		// the invariant for most of the inventory at once.
		const generic = sites.filter((site) => site.area === '*');

		expect(generic.length).toBeGreaterThan(0);
		expect(generic.filter((site) => !site.passesTtl)).toEqual([]);
	});
});
