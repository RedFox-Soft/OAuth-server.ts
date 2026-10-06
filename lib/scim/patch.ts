import {
	FORBIDDEN_KEYS,
	SCIM_ENTERPRISE_ATTRIBUTES,
	SCIM_ENTERPRISE_USER_SCHEMA,
	SCIM_PATCH_OP,
	SCIM_READ_ONLY_ATTRIBUTES,
	SCIM_USER_ATTRIBUTES,
	SCIM_USER_SCHEMA,
	type ScimAttribute
} from '../consts/scim.js';
import { ScimError } from './errors.js';
import { tokenize } from './filter.js';
import {
	assertNoForbiddenKeys,
	canonicalValue,
	type Leniency,
	type ScimObject
} from './resource.js';

/*
 * SCIM PATCH (RFC 7644 §3.5.2) applied to a working copy of the user's SCIM view, all or nothing: every
 * operation is applied to the copy first, and the copy is written only if none failed (spec FR-025).
 *
 * Our own applier rather than `scim-patch`, which issue #62 named: 0.9.3 rejects `REPLACE`, throws a
 * TypeError on a path-less `Remove`, stores `"False"` as a string, matches attribute names case-sensitively,
 * breaks on a `:` inside a filter value, validates nothing, and had two prototype-pollution advisories in
 * 2026 (research R11). The forms real clients send are a short list; resolving them against the declared
 * attribute table is smaller than wrapping that library safely.
 *
 * Tolerances, all governed by `scim.strict` (spec FR-034a): an operation name in any case, a path-less
 * add/replace (Okta's deactivation, Entra's multi-attribute updates), booleans as strings, a path naming
 * `password` or an attribute this server does not store (ignored), and a `replace` through a `type` filter
 * that matches nothing (Entra setting a work email the user did not have yet — appended), the manager
 * given as its bare id, and a `replace` of the manager with an empty string meaning remove it (both Entra).
 * In strict mode each is refused with 400.
 */

type Op = 'add' | 'replace' | 'remove';

const CORE_PREFIX = `${SCIM_USER_SCHEMA}:`;
const ENTERPRISE_PREFIX = `${SCIM_ENTERPRISE_USER_SCHEMA}:`;

function startsWithCi(text: string, prefix: string): boolean {
	return text.toLowerCase().startsWith(prefix.toLowerCase());
}

function named(
	attributes: readonly ScimAttribute[],
	name: string
): ScimAttribute | undefined {
	const lower = name.toLowerCase();
	return attributes.find((a) => a.name.toLowerCase() === lower);
}

interface Equality {
	attr: string;
	value: string | boolean;
}

/* A resolved target: an attribute (core or enterprise), optionally a value filter, optionally a sub-attribute. */
type Target =
	| { kind: 'ignored' }
	| { kind: 'enterpriseWhole' }
	| {
			kind: 'attribute';
			scope: 'core' | 'enterprise';
			attribute: ScimAttribute;
			filter?: Equality[];
			sub?: ScimAttribute;
	  };

function invalidPath(detail: string): ScimError {
	return new ScimError(400, 'invalidPath', detail);
}

function refuseOrIgnore(leniency: Leniency, error: ScimError): Target {
	if (leniency.strict) throw error;
	return { kind: 'ignored' };
}

/* `type eq "work"`, `value eq "x"`, `primary eq true`, joined by `and`. */
function parseValueFilter(text: string): Equality[] {
	const tokens = tokenize(text, invalidPath);
	const out: Equality[] = [];
	let i = 0;
	for (;;) {
		const attr = tokens[i++];
		const op = tokens[i++];
		const value = tokens[i++];
		if (
			attr?.kind !== 'word' ||
			op?.kind !== 'word' ||
			op.text.toLowerCase() !== 'eq'
		) {
			throw invalidPath('a value filter in a path supports only eq');
		}
		const name = attr.text.toLowerCase();
		if (name !== 'type' && name !== 'value' && name !== 'primary') {
			throw invalidPath(
				'a value filter in a path may test type, value or primary'
			);
		}
		if (value?.kind === 'string') {
			out.push({ attr: name, value: value.text });
		} else if (value?.kind === 'word' && /^(true|false)$/i.test(value.text)) {
			out.push({ attr: name, value: value.text.toLowerCase() === 'true' });
		} else {
			throw invalidPath(
				'a value filter compares with a quoted string or a boolean'
			);
		}
		if (i >= tokens.length) return out;
		const and = tokens[i++];
		if (and?.kind !== 'word' || and.text.toLowerCase() !== 'and') {
			throw invalidPath('value filter terms may only be joined by and');
		}
	}
}

/* Splits `attr[filter].sub` respecting quotes, so a `]` or `.` inside a quoted value is not structure. */
function splitPath(path: string): {
	attr: string;
	filter?: string;
	sub?: string;
} {
	const open = path.indexOf('[');
	if (open === -1) {
		const dot = path.indexOf('.');
		return dot === -1
			? { attr: path }
			: { attr: path.slice(0, dot), sub: path.slice(dot + 1) };
	}
	let i = open + 1;
	let quoted = false;
	for (; i < path.length; i++) {
		const c = path[i];
		if (c === '\\' && quoted) {
			i++;
			continue;
		}
		if (c === '"') quoted = !quoted;
		else if (c === ']' && !quoted) break;
	}
	if (i >= path.length)
		throw invalidPath('a value filter in the path is not closed');
	const rest = path.slice(i + 1);
	if (rest !== '' && !rest.startsWith('.')) {
		throw invalidPath('unexpected text after a value filter');
	}
	return {
		attr: path.slice(0, open),
		filter: path.slice(open + 1, i),
		sub: rest === '' ? undefined : rest.slice(1)
	};
}

export function resolvePath(path: string, leniency: Leniency): Target {
	if (FORBIDDEN_KEYS.some((k) => path.includes(k))) {
		throw invalidPath('the path names a forbidden key');
	}
	let scope: 'core' | 'enterprise' = 'core';
	let rest = path;
	if (startsWithCi(rest, ENTERPRISE_PREFIX)) {
		scope = 'enterprise';
		rest = rest.slice(ENTERPRISE_PREFIX.length);
	} else if (rest.toLowerCase() === SCIM_ENTERPRISE_USER_SCHEMA.toLowerCase()) {
		return { kind: 'enterpriseWhole' };
	} else if (startsWithCi(rest, CORE_PREFIX)) {
		rest = rest.slice(CORE_PREFIX.length);
	}
	const { attr, filter, sub } = splitPath(rest);
	const lower = attr.toLowerCase();

	if (scope === 'core' && SCIM_READ_ONLY_ATTRIBUTES.includes(lower)) {
		throw new ScimError(400, 'mutability', `${attr} cannot be changed`);
	}
	if (scope === 'core' && lower === 'password') {
		return refuseOrIgnore(
			leniency,
			new ScimError(
				400,
				'invalidValue',
				'the password attribute is not supported'
			)
		);
	}
	const attribute = named(
		scope === 'core' ? SCIM_USER_ATTRIBUTES : SCIM_ENTERPRISE_ATTRIBUTES,
		attr
	);
	if (!attribute) {
		return refuseOrIgnore(
			leniency,
			invalidPath(`${attr} is not an attribute of this resource`)
		);
	}
	if (
		filter !== undefined &&
		!(attribute.multiValued && attribute.type === 'complex')
	) {
		throw invalidPath(`${attribute.name} cannot be filtered`);
	}
	let subAttribute: ScimAttribute | undefined;
	if (sub !== undefined) {
		subAttribute = named(attribute.subAttributes ?? [], sub);
		if (!subAttribute)
			throw invalidPath(`${attribute.name}.${sub} is not an attribute`);
	}
	return {
		kind: 'attribute',
		scope,
		attribute,
		filter: filter === undefined ? undefined : parseValueFilter(filter),
		sub: subAttribute
	};
}

function containerFor(
	view: ScimObject,
	scope: 'core' | 'enterprise'
): ScimObject {
	if (scope === 'core') return view;
	const existing = view[SCIM_ENTERPRISE_USER_SCHEMA];
	if (
		typeof existing === 'object' &&
		existing !== null &&
		!Array.isArray(existing)
	) {
		return existing as ScimObject;
	}
	const created: ScimObject = {};
	view[SCIM_ENTERPRISE_USER_SCHEMA] = created;
	return created;
}

function matches(element: unknown, filter: Equality[]): boolean {
	if (typeof element !== 'object' || element === null) return false;
	const record = element as ScimObject;
	return filter.every(({ attr, value }) => {
		const actual = record[attr];
		return typeof value === 'string' && typeof actual === 'string'
			? actual.toLowerCase() === value.toLowerCase()
			: actual === value;
	});
}

function isObject(value: unknown): value is ScimObject {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function applyToAttribute(
	view: ScimObject,
	op: Op,
	target: Extract<Target, { kind: 'attribute' }>,
	value: unknown,
	leniency: Leniency
): void {
	const container = containerFor(view, target.scope);
	const { attribute, filter, sub } = target;
	const key = attribute.name;

	if (filter) {
		const list = Array.isArray(container[key])
			? [...(container[key] as unknown[])]
			: [];
		const hits = list.filter((element) => matches(element, filter));
		if (op === 'remove') {
			container[key] = sub
				? list.map((element) => {
						if (!hits.includes(element)) return element;
						const copy = { ...(element as ScimObject) };
						delete copy[sub.name];
						return copy;
					})
				: list.filter((element) => !hits.includes(element));
			return;
		}
		if (hits.length === 0) {
			/*
			 * Entra sets a work email or phone the user did not have with `replace emails[type eq "work"].value`.
			 * RFC 7644 §3.5.2.3 says that is `noTarget`; outside strict mode it is the entry the client meant.
			 */
			if (op === 'replace' && leniency.strict) {
				throw new ScimError(
					400,
					'noTarget',
					`no ${key} entry matches the filter`
				);
			}
			const seed: ScimObject = {};
			for (const { attr, value: v } of filter) seed[attr] = v;
			const added = sub
				? { ...seed, [sub.name]: canonicalValue(sub, value, leniency) }
				: {
						...seed,
						...(isObject(value)
							? (
									canonicalValue(attribute, [value], leniency) as ScimObject[]
								)[0]
							: {})
					};
			container[key] = [...list, added];
			return;
		}
		container[key] = list.map((element) => {
			if (!hits.includes(element)) return element;
			if (sub) {
				return {
					...(element as ScimObject),
					[sub.name]: canonicalValue(sub, value, leniency)
				};
			}
			const replacement = canonicalValue(attribute, [value], leniency);
			return Array.isArray(replacement) ? replacement[0] : replacement;
		});
		return;
	}

	if (sub) {
		const current = isObject(container[key])
			? { ...(container[key] as ScimObject) }
			: {};
		if (attribute.multiValued) {
			throw invalidPath(`a sub-attribute of ${key} needs a value filter`);
		}
		if (op === 'remove') delete current[sub.name];
		else current[sub.name] = canonicalValue(sub, value, leniency);
		container[key] = current;
		return;
	}

	if (
		op !== 'remove' &&
		value === '' &&
		attribute.type === 'complex' &&
		!attribute.multiValued
	) {
		/* Entra removes the manager with `replace` and an empty string rather than `remove`. */
		if (leniency.strict) {
			throw new ScimError(
				400,
				'invalidValue',
				`${key} cannot be set to an empty string; remove it instead`
			);
		}
		delete container[key];
		return;
	}
	if (op === 'remove') {
		delete container[key];
		return;
	}
	const incoming = canonicalValue(attribute, value, leniency);
	if (attribute.multiValued) {
		const values = Array.isArray(incoming) ? incoming : [incoming];
		if (op === 'replace') {
			container[key] = values;
			return;
		}
		const existing = Array.isArray(container[key])
			? (container[key] as unknown[])
			: [];
		const seen = new Set(existing.map((e) => JSON.stringify(e)));
		container[key] = [
			...existing,
			...values.filter((v) => !seen.has(JSON.stringify(v)))
		];
		return;
	}
	if (
		attribute.type === 'complex' &&
		isObject(incoming) &&
		isObject(container[key])
	) {
		/* §3.5.2.1/§3.5.2.3: sub-attributes not given are left as they are. */
		container[key] = { ...(container[key] as ScimObject), ...incoming };
		return;
	}
	container[key] = incoming;
}

function applyOne(
	view: ScimObject,
	op: Op,
	path: string,
	value: unknown,
	leniency: Leniency
): void {
	const target = resolvePath(path, leniency);
	if (target.kind === 'ignored') return;
	if (target.kind === 'enterpriseWhole') {
		if (op === 'remove') {
			delete view[SCIM_ENTERPRISE_USER_SCHEMA];
			return;
		}
		if (!isObject(value)) {
			throw new ScimError(
				400,
				'invalidValue',
				'the enterprise extension must be an object'
			);
		}
		for (const [key, v] of Object.entries(value)) {
			applyOne(view, op, `${ENTERPRISE_PREFIX}${key}`, v, leniency);
		}
		return;
	}
	if (op !== 'remove' && value === undefined) {
		throw new ScimError(400, 'invalidValue', `${op} needs a value`);
	}
	applyToAttribute(view, op, target, value, leniency);
}

function operationsOf(body: unknown): unknown[] {
	if (!isObject(body)) {
		throw new ScimError(
			400,
			'invalidSyntax',
			'the request body must be a JSON object'
		);
	}
	const schemas = body.schemas;
	if (Array.isArray(schemas) && !schemas.includes(SCIM_PATCH_OP)) {
		throw new ScimError(
			400,
			'invalidSyntax',
			`a PATCH body declares the ${SCIM_PATCH_OP} schema`
		);
	}
	const key = Object.keys(body).find((k) => k.toLowerCase() === 'operations');
	const operations = key ? body[key] : undefined;
	if (!Array.isArray(operations) || operations.length === 0) {
		throw new ScimError(
			400,
			'invalidSyntax',
			'Operations must be a non-empty array'
		);
	}
	return operations;
}

/* Applies every operation to a copy of `view`; throws, leaving `view` untouched, if any fails. */
export function applyPatch(
	view: ScimObject,
	body: unknown,
	leniency: Leniency
): ScimObject {
	assertNoForbiddenKeys(body, 'the request body');
	const working = structuredClone(view);
	for (const raw of operationsOf(body)) {
		if (!isObject(raw)) {
			throw new ScimError(
				400,
				'invalidSyntax',
				'each operation must be an object'
			);
		}
		const field = (name: string) =>
			raw[Object.keys(raw).find((k) => k.toLowerCase() === name) ?? name];
		const opText = field('op');
		if (typeof opText !== 'string') {
			throw new ScimError(400, 'invalidSyntax', 'each operation names an op');
		}
		const op = opText.toLowerCase();
		if (op !== 'add' && op !== 'replace' && op !== 'remove') {
			throw new ScimError(
				400,
				'invalidSyntax',
				`${opText} is not a PATCH operation`
			);
		}
		if (leniency.strict && opText !== op) {
			throw new ScimError(400, 'invalidSyntax', 'the op must be lower case');
		}
		const path = field('path');
		const value = field('value');

		if (path === undefined || path === '') {
			if (op === 'remove') {
				throw new ScimError(400, 'noTarget', 'remove needs a path');
			}
			/* Okta's `{"op":"replace","value":{"active":false}}`; Entra's multi-attribute replace. */
			if (leniency.strict) {
				throw new ScimError(400, 'invalidSyntax', 'an operation needs a path');
			}
			if (!isObject(value)) {
				throw new ScimError(
					400,
					'invalidValue',
					'a path-less operation needs an object value'
				);
			}
			for (const [key, v] of Object.entries(value)) {
				applyOne(working, op, key, v, leniency);
			}
			continue;
		}
		if (typeof path !== 'string') {
			throw new ScimError(400, 'invalidPath', 'path must be a string');
		}
		applyOne(working, op, path, value, leniency);
	}
	return working;
}
