import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

/*
 * Every value bound to a document column must be the document itself.
 *
 * Hand the datastore a pre-serialised object and it stores a jsonb *string containing JSON*. Reading
 * a row back by its key still returns exactly what was written, so every round trip looks perfect —
 * while every `doc->>'field'` predicate silently matches nothing. Sessions do not resume, grants are
 * not found, and nothing is logged. `lib/adapters/postgres/json.ts` records that its own first
 * version parsed the string instead of refusing it, which hid the defect completely.
 *
 * The read half is already covered: that module throws. The WRITE half cannot be proven without a
 * database, and Principle III forbids the default run touching one — `database/verify_postgres.ts`
 * §2 and §7 catch it and the merge gate never runs them. But the defect is a call-site spelling, and
 * the set of call sites is enumerable from the directory, which is exactly what a completeness guard
 * holds: the failure mode is the site somebody forgot, and no example-based test closes an absence.
 *
 * Positional rather than a substring sweep, because a sweep would be satisfied by the wrong thing in
 * both directions. `JSON.stringify` appears legitimately in this directory — in prose about date
 * encoding, and in the detector module itself — so a naive scan fails against correct code on day
 * one and gets "repaired" by weakening it. And a document bound in the wrong COLUMN is a different
 * defect that a keyword sweep would miss entirely.
 */

const POSTGRES = resolve(import.meta.dir, '../../lib/adapters/postgres');

/*
 * The detector, not a write site. Its two mentions of the forbidden spelling are the error message it
 * raises and the explanation of what it is for; guarding it would be guarding the guard.
 */
const NOT_A_WRITE_SITE = new Map([
	[
		'json.ts',
		'the detector for this very defect — its mentions are its error message'
	]
]);

/* The columns a record's document lives in: model areas use `payload`, everything else `doc`. */
const DOCUMENT_COLUMNS = new Set(['doc', 'payload']);

/*
 * A call that hands the datastore text where an object belongs. `JSON.stringify` is the one that
 * shipped; the others are here because they are the same mistake spelled differently, and a guard
 * that named only the spelling already made would be a guard against repeating history exactly.
 */
const SERIALISING =
	/\b(?:JSON\s*\.\s*stringify|toJSON|String)\s*\(|\.\s*toString\s*\(/;

interface Template {
	/* The template with each `${…}` replaced by a positional marker, so columns can be matched. */
	readonly shape: string;
	readonly expressions: readonly string[];
}

function modules(): string[] {
	return readdirSync(POSTGRES, { recursive: true, encoding: 'utf8' })
		.filter((entry) => entry.endsWith('.ts'))
		.filter((entry) => !NOT_A_WRITE_SITE.has(entry));
}

/*
 * Comments go before anything else looks at the source, and the scanner has to know about strings to
 * do it: `'https://…'` contains a line-comment opener, and removing from there to end of line would
 * silently truncate a statement into something that parses as innocent.
 */
function withoutComments(source: string): string {
	let out = '';
	let i = 0;
	while (i < source.length) {
		const two = source.slice(i, i + 2);
		if (two === '//') {
			while (i < source.length && source[i] !== '\n') i++;
			continue;
		}
		if (two === '/*') {
			i += 2;
			while (i < source.length && source.slice(i, i + 2) !== '*/') i++;
			i += 2;
			continue;
		}
		const ch = source[i];
		if (ch === "'" || ch === '"' || ch === '`') {
			out += ch;
			i++;
			while (i < source.length && source[i] !== ch) {
				if (source[i] === '\\') {
					out += source.slice(i, i + 2);
					i += 2;
					continue;
				}
				/* A nested template expression may hold another string; keep it verbatim either way. */
				out += source[i];
				i++;
			}
			out += source[i] ?? '';
			i++;
			continue;
		}
		out += ch;
		i++;
	}
	return out;
}

/* Every backtick template in the source, split into its literal shape and its interpolations. */
function templates(source: string): Template[] {
	const found: Template[] = [];
	let i = 0;
	while (i < source.length) {
		if (source[i] !== '`') {
			i++;
			continue;
		}
		i++;
		let shape = '';
		const expressions: string[] = [];
		while (i < source.length && source[i] !== '`') {
			if (source[i] === '\\') {
				i += 2;
				continue;
			}
			if (source.slice(i, i + 2) === '${') {
				i += 2;
				let depth = 1;
				let expression = '';
				while (i < source.length && depth > 0) {
					if (source[i] === '{') depth++;
					else if (source[i] === '}') depth--;
					if (depth > 0) expression += source[i];
					i++;
				}
				shape += `%%${expressions.length}%%`;
				expressions.push(expression.trim());
				continue;
			}
			shape += source[i];
			i++;
		}
		i++;
		found.push({ shape, expressions });
	}
	return found;
}

interface Binding {
	readonly file: string;
	readonly column: string;
	readonly expression: string;
}

/* The marker a `${…}` left behind, as it appears in a column list or a VALUES tuple. */
const MARKER = /%%(\d+)%%/;

/*
 * Two ways a document column is written, and both carry the value in an interpolation:
 * `INSERT INTO … (id, doc, expires_at) VALUES (…, ${doc}, …)` and `SET doc = ${doc}`.
 */
function bindings(file: string, template: Template): Binding[] {
	const found: Binding[] = [];
	const { shape, expressions } = template;

	const insert = /INSERT\s+INTO\s+\S+\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)/gi;
	for (const match of shape.matchAll(insert)) {
		const columns = match[1].split(',').map((c) => c.trim());
		const values = match[2].split(',').map((v) => v.trim());
		columns.forEach((column, index) => {
			if (!DOCUMENT_COLUMNS.has(column)) return;
			const marker = MARKER.exec(values[index] ?? '');
			if (!marker) return;
			found.push({ file, column, expression: expressions[Number(marker[1])] });
		});
	}

	const set = /\bSET\s+(\w+)\s*=\s*(%%\d+%%)/gi;
	for (const match of shape.matchAll(set)) {
		if (!DOCUMENT_COLUMNS.has(match[1])) continue;
		const marker = MARKER.exec(match[2]);
		if (!marker) continue;
		found.push({
			file,
			column: match[1],
			expression: expressions[Number(marker[1])]
		});
	}

	return found;
}

function allBindings(): Binding[] {
	return modules().flatMap((entry) => {
		const source = withoutComments(readFileSync(join(POSTGRES, entry), 'utf8'));
		return templates(source).flatMap((template) => bindings(entry, template));
	});
}

/**
 * @proves Every value the PostgreSQL adapter binds to a document column is the document itself, so a
 * predicate reaching inside a stored record cannot silently match nothing.
 */
describe('a document written to PostgreSQL', () => {
	const found = allBindings();

	/*
	 * Without this the guard passes over an empty set — which is worse than no guard, because it
	 * reports success. A renamed directory, a changed template style or a regression in the scanner
	 * all land here rather than in a green run. Same device as
	 * `fidelity_tier_isolation.spec.ts`: "finds the scripts it is guarding, so it cannot pass
	 * vacuously".
	 */
	it('is written at every site this guard claims to cover', () => {
		expect(found.length).toBeGreaterThan(0);

		const files = new Set(found.map((b) => b.file));
		expect(files).toContain('sqlAdapter.ts');
		expect(files).toContain('jwksStore.ts');

		const columns = new Set(found.map((b) => b.column));
		expect([...columns].sort()).toEqual(['doc', 'payload']);
	});

	it('is bound as the document itself, at every site', () => {
		const serialised = found
			.filter((b) => SERIALISING.test(b.expression))
			.map(
				(b) =>
					`${relative(process.cwd(), join(POSTGRES, b.file))} binds ${b.column} to ` +
					`\`${b.expression}\` — pass the object itself, not a serialised form of it`
			);

		expect(serialised).toEqual([]);
	});

	/*
	 * The detector is excluded by name rather than by accident, and an exclusion without a reason is
	 * how a list of exclusions becomes a list of things nobody re-examined.
	 */
	it('excludes only files with a recorded reason for being excluded', () => {
		const unexplained = [...NOT_A_WRITE_SITE.entries()]
			.filter(([, reason]) => !reason?.trim())
			.map(([file]) => file);

		expect(unexplained).toEqual([]);
	});
});
