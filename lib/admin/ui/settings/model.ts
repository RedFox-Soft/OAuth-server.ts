/*
 * The settings page's derivations, with no React and no fetch in them.
 *
 * Split out of the page for two reasons. The first is that this is where the logic that can be
 * *wrong* lives — which pane a setting lands on, which rows a search matches, which keys count as
 * edited, what a primary toggle resets on the way down — and none of it is reachable by a test while
 * it sits inside a component, because the repo has no DOM test harness. The second is that the page
 * was 732 lines doing five jobs; this is one of them.
 *
 * The types here mirror lib/admin/settings/catalog.ts rather than importing it. That is deliberate:
 * the catalog imports ApplicationConfig, which reaches the whole configuration layer, and pulling
 * that into the browser bundle to borrow an interface would be a poor trade. The mirror is checked
 * against the real descriptors at type level in test/admin/ui_settings_model.spec.ts, so it cannot
 * drift silently — which is the failure the old per-component copy invited.
 */

export type SettingType =
	'boolean' | 'string' | 'enum' | 'number' | 'string-array' | 'json';

export type SettingDomain =
	| 'grants'
	| 'request-security'
	| 'endpoints'
	| 'signin-abuse'
	| 'diagnostics'
	| 'integrations';

export interface Descriptor {
	key: string;
	domain: SettingDomain;
	group: string;
	label: string;
	summary: string;
	description: string;
	type: SettingType;
	options?: string[];
	unit?: string;
	dependsOn?: string;
	risk?: 'security';
	experimental?: boolean;
}

export interface DomainMeta {
	id: SettingDomain;
	label: string;
	blurb: string;
}

export type Values = Record<string, unknown>;

export interface SettingsResponse {
	catalog: Descriptor[];
	domains: DomainMeta[];
	values: Values;
	restartRequired: boolean;
	changedKeys: string[];
}

/*
 * The same equality the server uses to decide what really changed (lib/admin/settings/routes.ts),
 * and it has to be: a `string-array` or `json` setting is a fresh object on every edit, so an
 * identity comparison would report every one of them as dirty the moment the page loads.
 */
export const sameValue = (a: unknown, b: unknown): boolean =>
	JSON.stringify(a) === JSON.stringify(b);

/*
 * Whether this setting has a long form worth opening. Seventeen descriptions in the catalog are
 * shorter than the summary written for them, because the label already said everything — those rows
 * must not offer a disclosure that reveals less than the line above it.
 */
export const hasDetail = (d: Pick<Descriptor, 'summary' | 'description'>) =>
	d.description.length > d.summary.length;

/* The keys edited since the last load or save. */
export function dirtyKeys(values: Values, baseline: Values): string[] {
	return Object.keys(values).filter((k) => !sameValue(values[k], baseline[k]));
}

export interface GroupView {
	group: string;
	/*
	 * The switch that gates the group, shown in the card header: the group's single boolean with no
	 * `dependsOn`. Null for a group that is a set of values rather than a capability — Discovery and
	 * Login throttle both hold only always-live settings, and a header switch there would imply an off
	 * state that does not exist.
	 */
	primary: Descriptor | null;
	rows: Descriptor[];
}

/*
 * The cards for one pane, in catalog order — so the order of this page is decided by the order of
 * the catalog, and there is no second list to keep in step.
 */
export function groupsFor(
	catalog: Descriptor[],
	domain: SettingDomain
): GroupView[] {
	const order: string[] = [];
	const members = new Map<string, Descriptor[]>();
	for (const d of catalog) {
		if (d.domain !== domain) continue;
		const existing = members.get(d.group);
		if (existing) {
			existing.push(d);
		} else {
			members.set(d.group, [d]);
			order.push(d.group);
		}
	}
	return order.map((group) => {
		const all = members.get(group) ?? [];
		const primary =
			all.find((d) => d.type === 'boolean' && d.dependsOn === undefined) ??
			null;
		return { group, primary, rows: all.filter((d) => d !== primary) };
	});
}

/*
 * Whether a row's own prerequisite is met. A row whose prerequisite is unmet is shown disabled
 * rather than removed: hiding it meant an operator could not see what enabling a feature would let
 * them configure, and made a dirty value disappear from the page while still being submitted.
 */
export function isRowEnabled(d: Descriptor, values: Values): boolean {
	return d.dependsOn === undefined ? true : values[d.dependsOn] === true;
}

/*
 * Turning a primary off resets its boolean dependents to false. The server validates the merged
 * configuration, so a dependent left true under a disabled parent is refused on save — for a reason
 * the operator cannot see, since the row that holds it is disabled. Resetting keeps the submission
 * saveable; the rows stay on screen, so unlike before, the reset is visible while it happens.
 */
export function cascadeOff(
	catalog: Descriptor[],
	values: Values,
	primaryKey: string
): Values {
	const next: Values = { ...values, [primaryKey]: false };
	for (const d of catalog) {
		if (d.dependsOn === primaryKey && d.type === 'boolean') next[d.key] = false;
	}
	return next;
}

/* Case-insensitive match over the three things an operator might search by. */
export function matches(d: Descriptor, query: string): boolean {
	const q = query.trim().toLowerCase();
	if (q === '') return true;
	return (
		d.label.toLowerCase().includes(q) ||
		d.summary.toLowerCase().includes(q) ||
		d.key.toLowerCase().includes(q) ||
		d.group.toLowerCase().includes(q)
	);
}

/* Which panes hold an unsaved edit, so the sub-nav can say so. */
export function domainsWithDirty(
	catalog: Descriptor[],
	dirty: string[]
): Set<SettingDomain> {
	const wanted = new Set(dirty);
	const out = new Set<SettingDomain>();
	for (const d of catalog) if (wanted.has(d.key)) out.add(d.domain);
	return out;
}

/*
 * The user-code mask, as the two decisions it actually encodes.
 *
 * The stored value is a template: `*` becomes a random character and everything else is copied
 * through, with only asterisk, hyphen and space permitted (configs/configuration.ts). So the only
 * things an operator can decide are how many random characters the code has and how they are broken
 * up for reading — and a free-text field asks for neither of those, it asks for the encoding.
 *
 * Parsed rather than stored in pieces, because the mask is what the server reads and a second
 * representation in the settings would be a second thing to keep true.
 */
export type MaskSeparator = 'none' | 'hyphen' | 'space';

export interface MaskShape {
	length: number;
	separator: MaskSeparator;
	/* Characters per group between separators; 0 when there are none. */
	groupSize: number;
}

const SEPARATOR_CHAR: Record<MaskSeparator, string> = {
	none: '',
	hyphen: '-',
	space: ' '
};

/*
 * Read a stored mask back into the shape the editor offers, or null when it holds something the
 * editor cannot represent — uneven groups, or both separators at once. Null is the signal to fall
 * back to editing the template as text: refusing to show a valid configuration because this form
 * cannot draw it would be worse than the free-text field this replaces.
 */
export function parseMask(mask: unknown): MaskShape | null {
	if (typeof mask !== 'string' || !mask.includes('*')) return null;
	if (/[^-* ]/.test(mask)) return null;

	const hyphens = mask.includes('-');
	const spaces = mask.includes(' ');
	if (hyphens && spaces) return null;

	const separator: MaskSeparator = hyphens
		? 'hyphen'
		: spaces
			? 'space'
			: 'none';

	if (separator === 'none') {
		return { length: mask.length, separator, groupSize: 0 };
	}

	const groups = mask.split(SEPARATOR_CHAR[separator]);
	// Every group must be asterisks only, non-empty, and all the same width.
	if (groups.some((g) => g === '' || /[^*]/.test(g))) return null;
	if (new Set(groups.map((g) => g.length)).size !== 1) return null;

	return {
		length: groups.reduce((n, g) => n + g.length, 0),
		separator,
		groupSize: groups[0]?.length ?? 0
	};
}

/*
 * The group sizes worth offering for a given length: the divisors strictly between 1 and the length.
 *
 * Only divisors, because a group size that does not divide the length evenly leaves a short group at
 * the end — "***-*" — which reads badly and is not a shape this editor represents. Offering only
 * these is what keeps the control from being able to ask for something `buildMask` would have to
 * refuse.
 */
export function groupSizeOptions(length: number): number[] {
	const out: number[] = [];
	for (let size = 2; size < length; size += 1) {
		if (length % size === 0) out.push(size);
	}
	return out;
}

/*
 * Build a mask from the shape, which is what gets stored.
 *
 * Total by construction: a shape whose group size cannot divide the length evenly falls back to an
 * ungrouped mask rather than emitting the uneven groups `parseMask` would then refuse to read. The
 * round-trip property — everything this builds can be read back — is asserted in
 * test/admin/ui_settings_model.spec.ts across every combination the control can produce, and it is
 * what caught this: the first version happily built "***-*".
 */
export function buildMask(shape: MaskShape): string {
	const { length, separator, groupSize } = shape;
	const groupable =
		separator !== 'none' &&
		groupSize > 1 &&
		groupSize < length &&
		length % groupSize === 0;
	if (!groupable) return '*'.repeat(length);

	const groups: string[] = [];
	for (let i = 0; i < length; i += groupSize)
		groups.push('*'.repeat(groupSize));
	return groups.join(SEPARATOR_CHAR[separator]);
}

/*
 * The alphabet sizes the server draws from, mirrored from helpers/user_codes.ts. Mirrored rather
 * than imported for the reason the whole of this module is: that helper is server code. The two are
 * held together by test.
 */
const CHARSET_SIZE: Record<string, number> = {
	'base-20': 20,
	digits: 10
};

/*
 * How hard the code is to guess, in bits — the consequence the free-text mask field never showed.
 * Every asterisk is one character drawn from the charset, so the strength is length × log2(alphabet):
 * the shipped eight characters of base-20 are about 34 bits, the same eight digits about 27.
 *
 * Returned as bits rather than as a verdict. What counts as enough depends on how quickly the
 * verification endpoint refuses guesses, which is a different setting on a different pane, so the
 * page states the figure and leaves the judgement where it belongs.
 */
export function maskStrengthBits(
	mask: unknown,
	charset: unknown
): number | null {
	const shape = parseMask(mask);
	const size = typeof charset === 'string' ? CHARSET_SIZE[charset] : undefined;
	if (!shape || size === undefined) return null;
	return Math.round(shape.length * Math.log2(size) * 10) / 10;
}

/*
 * The authorization details types this server accepts, as something a form can edit.
 *
 * The stored value is a map of type identifier to a descriptor, and the descriptor's shape is fully
 * enumerable: a required label, optional constraints on the five common fields RFC 9396 §2 defines,
 * and a flag for unknown fields. That is why this is worth a form at all — the raw JSON textarea it
 * replaces let an operator name a field that does not exist, or put `allowed` on `identifier` where
 * it is refused, and learn about it from a 422 after saving.
 *
 * Two rules are enforced by *construction* here rather than restated: the field names come from a
 * fixed list, and `allowed` is only offered for the four list-valued fields. The remaining value
 * rules — a non-empty label, at least one type — are reported by `rarTypeIssues`, which is a
 * restatement and is therefore cross-checked against `validateConfiguration` itself in
 * test/admin/ui_settings_model.spec.ts. The server stays the authority; the form only aims to agree
 * with it early enough to be useful.
 *
 * `identifier` is single-valued, so a descriptor can only mark it required — fixing a permitted set
 * of per-resource identifiers would restrict nothing.
 */
export const RAR_LIST_FIELDS = [
	'actions',
	'locations',
	'datatypes',
	'privileges'
] as const;
export const RAR_FIELDS = [...RAR_LIST_FIELDS, 'identifier'] as const;

export type RarListField = (typeof RAR_LIST_FIELDS)[number];
export type RarField = (typeof RAR_FIELDS)[number];

export interface RarConstraint {
	required?: boolean;
	allowed?: string[];
}

/* One type, as the editor holds it: the map key lifted into the record so a list can be reordered. */
export interface RarType {
	id: string;
	label: string;
	fields: Partial<Record<RarField, RarConstraint>>;
	allowUnknownFields: boolean;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
	typeof v === 'object' && v !== null && !Array.isArray(v);

/*
 * Read the stored map into an ordered list. Unknown descriptor keys and unknown field names are
 * dropped rather than preserved: they are values the server refuses, so carrying them through the
 * editor would let it save something it cannot describe.
 */
export function parseRarTypes(value: unknown): RarType[] {
	if (!isRecord(value)) return [];
	return Object.entries(value).map(([id, raw]) => {
		const v = isRecord(raw) ? raw : {};
		const fields: Partial<Record<RarField, RarConstraint>> = {};
		if (isRecord(v.fields)) {
			for (const name of RAR_FIELDS) {
				const c = v.fields[name];
				if (!isRecord(c)) continue;
				const constraint: RarConstraint = {};
				if (typeof c.required === 'boolean') constraint.required = c.required;
				if (
					Array.isArray(c.allowed) &&
					(RAR_LIST_FIELDS as readonly string[]).includes(name)
				) {
					constraint.allowed = c.allowed.filter(
						(a): a is string => typeof a === 'string'
					);
				}
				fields[name] = constraint;
			}
		}
		return {
			id,
			label: typeof v.label === 'string' ? v.label : '',
			fields,
			allowUnknownFields: v.allowUnknownFields === true
		};
	});
}

/*
 * Back to the stored map. Empty optionals are omitted rather than written as empty objects: the
 * difference is invisible to the server but not to the review drawer, which would otherwise report a
 * change every time the editor was opened and closed.
 */
export function buildRarTypes(types: RarType[]): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const t of types) {
		const descriptor: Record<string, unknown> = { label: t.label };
		const fields: Record<string, unknown> = {};
		for (const name of RAR_FIELDS) {
			const c = t.fields[name];
			if (!c) continue;
			const constraint: Record<string, unknown> = {};
			if (c.required !== undefined) constraint.required = c.required;
			if (c.allowed?.length) constraint.allowed = [...c.allowed];
			fields[name] = constraint;
		}
		if (Object.keys(fields).length) descriptor.fields = fields;
		if (t.allowUnknownFields) descriptor.allowUnknownFields = true;
		out[t.id] = descriptor;
	}
	return out;
}

/*
 * What the server would refuse, reported while it can still be fixed. A restatement by necessity,
 * held to the real validator by test rather than by hope.
 */
export function rarTypeIssues(types: RarType[], enabled: boolean): string[] {
	const issues: string[] = [];
	if (enabled && types.length === 0) {
		issues.push('At least one type is needed while the feature is on.');
	}
	const seen = new Set<string>();
	for (const t of types) {
		const name = t.id.trim() === '' ? '(unnamed type)' : t.id;
		if (t.id.trim() === '') issues.push('A type needs an identifier.');
		else if (seen.has(t.id))
			issues.push(`Two types share the identifier ${t.id}.`);
		seen.add(t.id);
		if (t.label.trim() === '') {
			issues.push(
				`${name} needs a label — it is what the consent screen shows.`
			);
		}
		for (const field of RAR_LIST_FIELDS) {
			const allowed = t.fields[field]?.allowed;
			if (allowed && allowed.some((a) => a.trim() === '')) {
				issues.push(`${name}: ${field} has an empty permitted value.`);
			}
		}
	}
	return issues;
}

export interface ThrottleRate {
	guessesPerDay: number;
	cap: number;
	ceilingSeconds: number;
}

/*
 * What the login throttle's three numbers actually add up to: how many passwords one address may try
 * per day against one identity, once its lockouts have escalated.
 *
 * Worth computing because the consequence is not legible from the numbers. `windowFor` doubles the
 * window from `windowSeconds` and clamps at `windowCeilingSeconds` (login_throttle/consts.ts), so
 * with the shipped defaults the ladder runs 15 → 30 → 60 minutes and from the third lockout onward
 * only the ceiling is in force. From there an attacker spends `failureCap` attempts and waits out the
 * ceiling, which is a steady rate of cap × 86400 ÷ ceiling — 120 a day by default. The counter is
 * kept for 24 hours from the *most recent* failure, so a sustained attack never decays back down a
 * step and the steady rate is the real one.
 *
 * Asymptotic on purpose: the first few lockouts are shorter, so the true total over the first hours is
 * somewhat higher. Stating the settled rate is what makes two configurations comparable, and it is
 * the number the catalog's own description already quotes.
 *
 * Returns null rather than a number whenever either input is not a usable positive value — the page
 * holds half-typed values while an operator edits, and a hint that reads "Infinity guesses a day"
 * would be worse than no hint.
 */
export function throttleRate(values: Values): ThrottleRate | null {
	const cap = values['loginThrottle.failureCap'];
	const ceilingSeconds = values['loginThrottle.windowCeilingSeconds'];
	if (typeof cap !== 'number' || !Number.isFinite(cap) || cap <= 0) return null;
	if (
		typeof ceilingSeconds !== 'number' ||
		!Number.isFinite(ceilingSeconds) ||
		ceilingSeconds <= 0
	) {
		return null;
	}
	return {
		cap,
		ceilingSeconds,
		guessesPerDay: Math.round((cap * 86400) / ceilingSeconds)
	};
}

/* A duration in the largest unit that divides it exactly, for prose rather than for a form field. */
export function humanDuration(seconds: number): string {
	const plural = (n: number, unit: string) =>
		`${n} ${unit}${n === 1 ? '' : 's'}`;
	if (seconds % 3600 === 0) return plural(seconds / 3600, 'hour');
	if (seconds % 60 === 0) return plural(seconds / 60, 'minute');
	return plural(seconds, 'second');
}

export interface Change {
	key: string;
	label: string;
	group: string;
	from: unknown;
	to: unknown;
	risk?: 'security';
}

/*
 * The pending edits, as something an operator can read before committing them. Ordered by the
 * catalog so the review list and the page agree, and carrying the risk flag so the confirmation step
 * does not have to look descriptors up again.
 */
export function pendingChanges(
	catalog: Descriptor[],
	values: Values,
	baseline: Values
): Change[] {
	const dirty = new Set(dirtyKeys(values, baseline));
	return catalog
		.filter((d) => dirty.has(d.key))
		.map((d) => ({
			key: d.key,
			label: d.label,
			group: d.group,
			from: baseline[d.key],
			to: values[d.key],
			risk: d.risk
		}));
}

/* The pending edits that need confirming rather than merely saving. */
export const riskyChanges = (changes: Change[]): Change[] =>
	changes.filter((c) => c.risk === 'security');
