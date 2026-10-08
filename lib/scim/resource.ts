import { Value } from '@sinclair/typebox/value';

import {
	EndUserProfile,
	type BucketGroup,
	type ProvisioningConnection,
	type User
} from '../adapters/types.js';
import {
	FORBIDDEN_KEYS,
	SCIM_ENTERPRISE_ATTRIBUTES,
	SCIM_ENTERPRISE_USER_SCHEMA,
	SCIM_GROUP_SCHEMA,
	SCIM_READ_ONLY_ATTRIBUTES,
	SCIM_USER_ATTRIBUTES,
	SCIM_USER_SCHEMA,
	type ScimAttribute
} from '../consts/scim.js';
import type { UpdateEndUserInput } from '../end_users/service.js';
import { ScimError } from './errors.js';

/*
 * Between a SCIM User and an end user (specs/070 research R12). The profile was stored in SCIM's own shape
 * in part 1, so the mapping is field for field; what this module adds is the boundary — which names are
 * attributes, what a value may be, and which leniencies the request is granted.
 *
 * The leniencies are the ones `scim.strict` governs (spec FR-034a), and this is their one home: an
 * attribute this server does not store is dropped, a `password` is dropped, and a boolean written as a
 * string is read as one. In strict mode each of those is a 400 instead. Attribute names are matched
 * case-insensitively in both modes — RFC 7643 §2.1 makes them so, which is not a leniency.
 */

export type ScimObject = Record<string, unknown>;

export interface Leniency {
	strict: boolean;
}

export function scimLocation(
	base: string,
	id: string,
	type: 'Users' | 'Groups' = 'Users'
): string {
	return `${base}/${type}/${encodeURIComponent(id)}`;
}

/*
 * The SCIM view of a user. Absent values are omitted, never null; nothing about credentials, ever. `groups`
 * are the requesting connection's groups the user is in (RFC 7643 §4.1.2, read-only), omitted when none.
 */
export function toScim(
	user: User,
	base: string,
	groups: readonly Pick<BucketGroup, '_id' | 'displayName'>[] = []
): ScimObject {
	const profile = user.profile ?? {};
	const emails = profile.emails?.length
		? profile.emails.map((e) => ({ ...e }))
		: [{ value: user.email, primary: true }];
	const resource: ScimObject = {
		schemas: [SCIM_USER_SCHEMA],
		id: user._id
	};
	if (user.externalId !== undefined) resource.externalId = user.externalId;
	resource.userName = user.userName ?? user.email;
	if (profile.name) resource.name = { ...profile.name };
	for (const key of [
		'displayName',
		'nickName',
		'title',
		'preferredLanguage',
		'locale',
		'timezone'
	] as const) {
		if (profile[key] !== undefined) resource[key] = profile[key];
	}
	resource.active = user.active;
	resource.emails = emails;
	if (profile.phoneNumbers?.length) {
		resource.phoneNumbers = profile.phoneNumbers.map((p) => ({ ...p }));
	}
	if (groups.length) {
		resource.groups = groups.map((g) => ({
			value: g._id,
			display: g.displayName,
			$ref: scimLocation(base, g._id, 'Groups'),
			type: 'direct'
		}));
	}
	if (profile.enterprise && Object.keys(profile.enterprise).length) {
		resource.schemas = [SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA];
		resource[SCIM_ENTERPRISE_USER_SCHEMA] = structuredClone(profile.enterprise);
	}
	resource.meta = {
		resourceType: 'User',
		created: user.createdAt.toISOString(),
		lastModified: user.updatedAt.toISOString(),
		location: scimLocation(base, user._id)
	};
	return resource;
}

function isRecord(value: unknown): value is ScimObject {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/* Any forbidden key anywhere in a body is refused before anything else looks at it. */
export function assertNoForbiddenKeys(value: unknown, where = 'value'): void {
	if (Array.isArray(value)) {
		for (const item of value) assertNoForbiddenKeys(item, where);
		return;
	}
	if (!isRecord(value)) return;
	for (const key of Object.keys(value)) {
		if (FORBIDDEN_KEYS.includes(key)) {
			throw new ScimError(
				400,
				'invalidValue',
				`${where} names a forbidden key`
			);
		}
		assertNoForbiddenKeys(value[key], where);
	}
}

const BOOLEAN_STRING = /^(true|false)$/i;

function readBoolean(
	value: unknown,
	path: string,
	leniency: Leniency
): unknown {
	if (typeof value === 'boolean') return value;
	if (typeof value === 'string' && BOOLEAN_STRING.test(value)) {
		/* Entra without `aadOptscim062020` writes `"False"` (specs/070 research R21). */
		if (leniency.strict) {
			throw new ScimError(
				400,
				'invalidSyntax',
				`${path} must be a JSON boolean`
			);
		}
		return value.toLowerCase() === 'true';
	}
	return value;
}

function attributeNamed(
	attributes: readonly ScimAttribute[],
	name: string
): ScimAttribute | undefined {
	const lower = name.toLowerCase();
	return attributes.find((a) => a.name.toLowerCase() === lower);
}

/* One complex value with its sub-attribute names canonicalised; unknown sub-attributes dropped or refused. */
function canonicalComplex(
	value: unknown,
	attribute: ScimAttribute,
	path: string,
	leniency: Leniency
): unknown {
	if (!isRecord(value)) return value;
	const out: ScimObject = {};
	for (const [key, raw] of Object.entries(value)) {
		const sub = attributeNamed(attribute.subAttributes ?? [], key);
		if (!sub) {
			if (leniency.strict) {
				throw new ScimError(
					400,
					'invalidSyntax',
					`${path}.${key} is not an attribute of this resource`
				);
			}
			continue;
		}
		out[sub.name] =
			sub.type === 'boolean'
				? readBoolean(raw, `${path}.${sub.name}`, leniency)
				: raw;
	}
	return out;
}

export function canonicalValue(
	attribute: ScimAttribute,
	value: unknown,
	leniency: Leniency
): unknown {
	if (attribute.type === 'boolean') {
		return readBoolean(value, attribute.name, leniency);
	}
	if (attribute.type !== 'complex') return value;
	if (
		!attribute.multiValued &&
		typeof value === 'string' &&
		attributeNamed(attribute.subAttributes ?? [], 'value')
	) {
		/* Entra sends the manager as the bare id, `"manager": "<id>"` (research R21). */
		if (leniency.strict) {
			throw new ScimError(
				400,
				'invalidSyntax',
				`${attribute.name} must be an object`
			);
		}
		return { value };
	}
	if (attribute.multiValued) {
		return Array.isArray(value)
			? value.map((v) =>
					canonicalComplex(v, attribute, attribute.name, leniency)
				)
			: value;
	}
	return canonicalComplex(value, attribute, attribute.name, leniency);
}

function canonicalEnterprise(value: unknown, leniency: Leniency): ScimObject {
	if (!isRecord(value)) {
		throw new ScimError(
			400,
			'invalidValue',
			'the enterprise extension must be an object'
		);
	}
	const out: ScimObject = {};
	for (const [key, raw] of Object.entries(value)) {
		const attribute = attributeNamed(SCIM_ENTERPRISE_ATTRIBUTES, key);
		if (!attribute) {
			if (leniency.strict) {
				throw new ScimError(
					400,
					'invalidSyntax',
					`${key} is not an attribute of the enterprise extension`
				);
			}
			continue;
		}
		out[attribute.name] = canonicalValue(attribute, raw, leniency);
	}
	return out;
}

/*
 * A request's User object reduced to the attributes this server stores, under their declared names. Read-only
 * attributes are ignored (RFC 7644 §3.5.1); `password` and anything undeclared are dropped, or refused in
 * strict mode.
 */
export function canonicalUser(body: unknown, leniency: Leniency): ScimObject {
	if (!isRecord(body)) {
		throw new ScimError(
			400,
			'invalidSyntax',
			'the request body must be a JSON object'
		);
	}
	assertNoForbiddenKeys(body, 'the request body');
	const out: ScimObject = {};
	for (const [key, raw] of Object.entries(body)) {
		const lower = key.toLowerCase();
		if (SCIM_READ_ONLY_ATTRIBUTES.includes(lower)) continue;
		if (lower === 'password') {
			/* IPSIE §6.1.2: not supported. Okta sends one on every create regardless (research R21). */
			if (leniency.strict) {
				throw new ScimError(
					400,
					'invalidValue',
					'the password attribute is not supported'
				);
			}
			continue;
		}
		if (lower === SCIM_ENTERPRISE_USER_SCHEMA.toLowerCase()) {
			out[SCIM_ENTERPRISE_USER_SCHEMA] = canonicalEnterprise(raw, leniency);
			continue;
		}
		const attribute = attributeNamed(SCIM_USER_ATTRIBUTES, key);
		if (!attribute) {
			if (leniency.strict) {
				throw new ScimError(
					400,
					'invalidSyntax',
					`${key} is not an attribute of this resource`
				);
			}
			continue;
		}
		if (attribute.mutability === 'readOnly') {
			/* RFC 7644 §3.5.1: ignored. A User's `groups` changes through /Groups. */
			if (leniency.strict) {
				throw new ScimError(
					400,
					'mutability',
					`${attribute.name} is read-only`
				);
			}
			continue;
		}
		out[attribute.name] = canonicalValue(attribute, raw, leniency);
	}
	return out;
}

/* What a canonical User asks the store to hold. `active` undefined means "not asserted". */
export interface DesiredUser {
	userName: string;
	externalId?: string;
	active?: boolean;
	email: string;
	profile: EndUserProfile;
}

const PROFILE_SCALARS = [
	'displayName',
	'nickName',
	'title',
	'preferredLanguage',
	'locale',
	'timezone'
] as const;

/* The sign-in address: the primary email, else the work one, else the first (spec, Edge Cases). */
function loginEmailOf(
	emails: { value: string; type?: string; primary?: boolean }[]
): string {
	const chosen =
		emails.find((e) => e.primary === true) ??
		emails.find((e) => e.type?.toLowerCase() === 'work') ??
		emails[0];
	return chosen.value;
}

export function desiredUserOf(canonical: ScimObject): DesiredUser {
	const userName = canonical.userName;
	if (
		typeof userName !== 'string' ||
		userName.trim() === '' ||
		userName.length > 256
	) {
		throw new ScimError(
			400,
			'invalidValue',
			'userName is required and must be a string of at most 256 characters'
		);
	}
	const externalId = canonical.externalId;
	if (
		externalId !== undefined &&
		(typeof externalId !== 'string' ||
			externalId === '' ||
			externalId.length > 256)
	) {
		throw new ScimError(
			400,
			'invalidValue',
			'externalId must be a string of at most 256 characters'
		);
	}
	const active = canonical.active;
	if (active !== undefined && typeof active !== 'boolean') {
		throw new ScimError(400, 'invalidValue', 'active must be a boolean');
	}

	const profile: Record<string, unknown> = {};
	if (canonical.name !== undefined) profile.name = canonical.name;
	for (const key of PROFILE_SCALARS) {
		if (canonical[key] !== undefined) profile[key] = canonical[key];
	}
	if (canonical.emails !== undefined) profile.emails = canonical.emails;
	if (canonical.phoneNumbers !== undefined)
		profile.phoneNumbers = canonical.phoneNumbers;
	const enterprise = canonical[SCIM_ENTERPRISE_USER_SCHEMA];
	if (isRecord(enterprise) && Object.keys(enterprise).length) {
		profile.enterprise = enterprise;
	}
	if (!Value.Check(EndUserProfile, profile)) {
		const first = [...Value.Errors(EndUserProfile, profile)][0];
		const where = first?.path
			? first.path.replace(/^\//, '').replaceAll('/', '.')
			: 'a value';
		throw new ScimError(
			400,
			'invalidValue',
			`${where} is not a valid value for this attribute`
		);
	}
	const emails = profile.emails ?? [];
	if (!emails.length || !emails.some((e) => e.value.trim() !== '')) {
		/* The email is the account's password login and its reset address (spec, Assumptions). */
		throw new ScimError(400, 'invalidValue', 'at least one email is required');
	}
	return {
		userName,
		externalId,
		active,
		email: loginEmailOf(emails),
		profile
	};
}

/* The SCIM attribute names whose value differs, for the audit entry — names only, never values. */
function changedNames(user: User, desired: DesiredUser): string[] {
	const names: string[] = [];
	const same = (a: unknown, b: unknown) =>
		JSON.stringify(a) === JSON.stringify(b);
	if (desired.userName !== user.userName) names.push('userName');
	if (desired.externalId !== user.externalId) names.push('externalId');
	if (desired.active !== undefined && desired.active !== user.active)
		names.push('active');
	const before = user.profile ?? {};
	const after = desired.profile;
	if (!same(before.name, after.name)) names.push('name');
	for (const key of PROFILE_SCALARS) {
		if (!same(before[key], after[key])) names.push(key);
	}
	if (!same(before.emails, after.emails) || desired.email !== user.email)
		names.push('emails');
	if (!same(before.phoneNumbers, after.phoneNumbers))
		names.push('phoneNumbers');
	const ent = (p: EndUserProfile) => p.enterprise ?? {};
	for (const attribute of SCIM_ENTERPRISE_ATTRIBUTES) {
		const k = attribute.name as keyof NonNullable<EndUserProfile['enterprise']>;
		if (!same(ent(before)[k], ent(after)[k])) names.push(attribute.name);
	}
	return names;
}

function sameProfile(
	a: EndUserProfile | undefined,
	b: EndUserProfile
): boolean {
	return JSON.stringify(a ?? {}) === JSON.stringify(b);
}

/*
 * The service input that makes `user` look like `desired`, and the names of what changes. An empty
 * `changes` means the request asserted what is already stored: nothing is written and nothing is audited
 * (spec FR-040).
 */
export function updateFor(
	user: User,
	desired: DesiredUser,
	connection: ProvisioningConnection
): { input: UpdateEndUserInput; changes: string[] } {
	const changes = changedNames(user, desired);
	const input: UpdateEndUserInput = {};
	if (desired.userName !== user.userName) input.userName = desired.userName;
	if (desired.externalId !== user.externalId) {
		/* A key present with undefined removes the field (the store's patch rule). */
		Object.assign(input, { externalId: desired.externalId });
	}
	if (desired.active !== undefined && desired.active !== user.active) {
		input.active = desired.active;
	}
	if (desired.email.toLowerCase() !== user.email) {
		input.email = desired.email;
		input.verified = connection.emailTrust === 'trusted';
	}
	if (!sameProfile(user.profile, desired.profile))
		input.profile = desired.profile;
	return { input, changes };
}

/* The SCIM attribute names a create stores, for the audit entry. */
export function createdNames(desired: DesiredUser): string[] {
	const names = ['userName', 'emails'];
	if (desired.externalId !== undefined) names.push('externalId');
	if (desired.active !== undefined) names.push('active');
	const p = desired.profile;
	if (p.name) names.push('name');
	for (const key of PROFILE_SCALARS) if (p[key] !== undefined) names.push(key);
	if (p.phoneNumbers) names.push('phoneNumbers');
	for (const attribute of SCIM_ENTERPRISE_ATTRIBUTES) {
		const k = attribute.name as keyof NonNullable<EndUserProfile['enterprise']>;
		if (p.enterprise?.[k] !== undefined) names.push(attribute.name);
	}
	return names;
}

/*
 * The canonical working copy a PATCH applies to: the SCIM view without what a request may not change, so an
 * operation can only ever touch a declared attribute.
 */
export function patchableView(user: User, base: string): ScimObject {
	const view = toScim(user, base);
	delete view.schemas;
	delete view.id;
	delete view.meta;
	return view;
}

/*
 * The SCIM view of a group. `members` is omitted when the caller excluded it (`excludedAttributes=members`,
 * which IPSIE AL SCIM §6.2.3 asks clients to send when listing) and `[]` when the group is empty; a member
 * carries no `display`, which RFC 7643 makes optional and which would cost a read of every member.
 */
export function toScimGroup(
	group: BucketGroup,
	base: string,
	members: readonly string[] | undefined
): ScimObject {
	const resource: ScimObject = {
		schemas: [SCIM_GROUP_SCHEMA],
		id: group._id
	};
	if (group.externalId !== undefined) resource.externalId = group.externalId;
	resource.displayName = group.displayName;
	if (members !== undefined) {
		resource.members = members.map((id) => ({
			value: id,
			$ref: scimLocation(base, id),
			type: 'User'
		}));
	}
	resource.meta = {
		resourceType: 'Group',
		created: group.createdAt.toISOString(),
		lastModified: group.updatedAt.toISOString(),
		location: scimLocation(base, group._id, 'Groups')
	};
	return resource;
}
