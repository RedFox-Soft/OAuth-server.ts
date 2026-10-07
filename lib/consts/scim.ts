/*
 * SCIM 2.0 declarations: schema URNs, the attributes this server stores, and the limits it applies.
 *
 * One table drives `/Schemas`, the filter parser and the PATCH applier, so what the server advertises and
 * what it accepts cannot drift apart — an attribute is resolvable in a path exactly when it is declared
 * here. Import-free, like every module in lib/consts.
 *
 * The attribute set is part 1's `EndUserProfile` plus the identity fields (specs/070 data-model). Nothing
 * here describes a credential: IPSIE AL SCIM §6.1.2 forbids `password`, and the schemas say so by omission.
 */

export const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const SCIM_GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
export const SCIM_ENTERPRISE_USER_SCHEMA =
	'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
export const SCIM_LIST_RESPONSE =
	'urn:ietf:params:scim:api:messages:2.0:ListResponse';
export const SCIM_PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
export const SCIM_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';
export const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA =
	'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig';
export const SCIM_RESOURCE_TYPE_SCHEMA =
	'urn:ietf:params:scim:schemas:core:2.0:ResourceType';
export const SCIM_SCHEMA_SCHEMA =
	'urn:ietf:params:scim:schemas:core:2.0:Schema';

export const SCIM_MEDIA_TYPE = 'application/scim+json';

/* Beneath a bucket's issuer. */
export const SCIM_BASE_PATH = '/scim/v2';

/*
 * Every SCIM route, in Elysia's declaration form, bare; each is mounted again beneath `/:bucket`. One table
 * for the plugin, the route classification and the completeness guards, so a route cannot be served without
 * being classified or audited. `mutates` marks the routes IPSIE AL SCIM §8 requires to be logged.
 */
export const SCIM_ROUTES = [
	{
		method: 'GET',
		path: `${SCIM_BASE_PATH}/ServiceProviderConfig`,
		mutates: false
	},
	{ method: 'GET', path: `${SCIM_BASE_PATH}/ResourceTypes`, mutates: false },
	{
		method: 'GET',
		path: `${SCIM_BASE_PATH}/ResourceTypes/:resourceTypeId`,
		mutates: false
	},
	{ method: 'GET', path: `${SCIM_BASE_PATH}/Schemas`, mutates: false },
	{
		method: 'GET',
		path: `${SCIM_BASE_PATH}/Schemas/:schemaId`,
		mutates: false
	},
	{ method: 'GET', path: `${SCIM_BASE_PATH}/Users`, mutates: false },
	{ method: 'POST', path: `${SCIM_BASE_PATH}/Users`, mutates: true },
	{ method: 'GET', path: `${SCIM_BASE_PATH}/Users/:userId`, mutates: false },
	{ method: 'PUT', path: `${SCIM_BASE_PATH}/Users/:userId`, mutates: true },
	{ method: 'PATCH', path: `${SCIM_BASE_PATH}/Users/:userId`, mutates: true },
	{ method: 'DELETE', path: `${SCIM_BASE_PATH}/Users/:userId`, mutates: true },
	{ method: 'GET', path: `${SCIM_BASE_PATH}/Groups`, mutates: false },
	{ method: 'POST', path: `${SCIM_BASE_PATH}/Groups`, mutates: true },
	{ method: 'GET', path: `${SCIM_BASE_PATH}/Groups/:groupId`, mutates: false },
	{ method: 'PUT', path: `${SCIM_BASE_PATH}/Groups/:groupId`, mutates: true },
	{ method: 'PATCH', path: `${SCIM_BASE_PATH}/Groups/:groupId`, mutates: true },
	{ method: 'DELETE', path: `${SCIM_BASE_PATH}/Groups/:groupId`, mutates: true }
] as const;

/* Whether a route pattern (as Elysia reports it) is a SCIM route, bare or beneath a bucket. */
export function isScimRoute(route: string | undefined): boolean {
	if (!route) return false;
	const bare = route.startsWith('/:bucket/')
		? route.slice('/:bucket'.length)
		: route;
	return bare === SCIM_BASE_PATH || bare.startsWith(`${SCIM_BASE_PATH}/`);
}

/*
 * Whether a request path lies beneath a SCIM base — the root one or a bucket's — whether or not anything
 * is mounted there. For a request no route matched, which has no pattern for `isScimRoute` to read.
 */
export function isScimPath(pathname: string): boolean {
	const bare = /^\/[^/]+\/scim\/v2(\/|$)/.test(pathname)
		? pathname.slice(pathname.indexOf('/', 1))
		: pathname;
	return bare === SCIM_BASE_PATH || bare.startsWith(`${SCIM_BASE_PATH}/`);
}

/*
 * RFC 9728 metadata for a bucket's SCIM resource. The well-known segment is inserted before the resource's
 * path (§3.1), so a path-addressed bucket's document cannot be produced by prefixing and is its own route.
 */
export const SCIM_METADATA_ROUTE = `/.well-known/oauth-protected-resource${SCIM_BASE_PATH}`;
export const SCIM_METADATA_BUCKET_ROUTE = `/.well-known/oauth-protected-resource/:bucket${SCIM_BASE_PATH}`;

/* IPSIE AL SCIM §6.1.5: a page SHOULD hold at most 1,000 users. */
export const SCIM_MAX_PAGE = 1000;
export const SCIM_DEFAULT_PAGE = 100;

/*
 * Far above any filter a provisioning client sends (Entra's longest is the work-email form, under 100
 * characters) and low enough that the tokenizer's work is bounded before it starts.
 */
export const SCIM_MAX_FILTER_LENGTH = 1024;

/* The largest valid user is a few KiB; anything near this is not a user. */
export const SCIM_MAX_BODY_BYTES = 256 * 1024;

/*
 * A static token's prefix. Makes a static token and an opaque access token distinguishable without a
 * lookup, lets one be accepted with no `Bearer` scheme (Okta's header mode sends the configured value
 * verbatim), and lets a secret scanner recognise one that leaked.
 */
export const STATIC_TOKEN_PREFIX = 'scimst_';

/* The OAuth client a connection's key or secret credential authenticates as is `scim-<connectionId>`. */
export const CONNECTION_CLIENT_PREFIX = 'scim-';

/* The only scope a connection's token carries (IPSIE AL SCIM §4.1). */
export const SCIM_SCOPE = 'scim';

/*
 * Never a path segment or an object key, whatever a request says. Refused before any operation applies,
 * because a patch applier that writes one of these through a computed key pollutes every object in the
 * process — the class of defect two scim-patch advisories were in 2026 (specs/070 R11).
 */
export const FORBIDDEN_KEYS: readonly string[] = [
	'__proto__',
	'constructor',
	'prototype'
];

export type ScimMutability = 'readOnly' | 'readWrite';

export interface ScimAttribute {
	readonly name: string;
	readonly type: 'string' | 'boolean' | 'complex';
	readonly multiValued: boolean;
	readonly required: boolean;
	readonly caseExact: boolean;
	readonly mutability: ScimMutability;
	readonly uniqueness: 'none' | 'server';
	readonly description: string;
	readonly subAttributes?: readonly ScimAttribute[];
}

const simple = (
	name: string,
	description: string,
	extra: Partial<ScimAttribute> = {}
): ScimAttribute => ({
	name,
	type: 'string',
	multiValued: false,
	required: false,
	caseExact: false,
	mutability: 'readWrite',
	uniqueness: 'none',
	description,
	...extra
});

/* `emails` and `phoneNumbers` share one shape, the same `ProfileContact` part 1 stores. */
const contactParts: readonly ScimAttribute[] = [
	simple('value', 'The address or number itself.'),
	simple('type', 'A label such as "work" or "home".'),
	simple('primary', 'Whether this is the preferred entry.', {
		type: 'boolean'
	})
];

export const SCIM_USER_ATTRIBUTES: readonly ScimAttribute[] = [
	simple(
		'userName',
		'The name the directory knows the user by. Unique in the bucket, compared case-insensitively.',
		{ required: true, uniqueness: 'server' }
	),
	simple(
		'externalId',
		'The identifier the directory assigned. Unique within the provisioning connection (RFC 7643 §3.1).',
		{ caseExact: true }
	),
	{
		...simple('name', 'The components of the user’s name.'),
		type: 'complex',
		subAttributes: [
			simple('formatted', 'The full name, formatted for display.'),
			simple('familyName', 'The family name.'),
			simple('givenName', 'The given name.'),
			simple('middleName', 'The middle name.'),
			simple('honorificPrefix', 'A title such as "Ms."'),
			simple('honorificSuffix', 'A suffix such as "III".')
		]
	},
	simple('displayName', 'The name shown to others.'),
	simple('nickName', 'A casual name.'),
	simple('title', 'A job title.'),
	simple('preferredLanguage', 'The preferred language, as a language tag.'),
	simple('locale', 'The locale used for formatting, as a language tag.'),
	simple('timezone', 'An IANA time zone such as "Europe/Berlin".'),
	simple(
		'active',
		'Whether the user may sign in. Setting it false ends every session and token at once.',
		{ type: 'boolean' }
	),
	{
		...simple(
			'emails',
			'Email addresses. The primary one, else the work one, else the first, is the sign-in address.'
		),
		type: 'complex',
		multiValued: true,
		required: true,
		subAttributes: contactParts
	},
	{
		...simple('phoneNumbers', 'Phone numbers.'),
		type: 'complex',
		multiValued: true,
		subAttributes: contactParts
	},
	/*
	 * Read-only, as RFC 7643 §4.1.2 declares it: membership is changed through the Group resource. Lists only the
	 * requesting connection's groups — another owner's groups are not this client's business.
	 */
	{
		...simple(
			'groups',
			'The groups of this connection the user belongs to. Changed through /Groups, never here.',
			{ mutability: 'readOnly' }
		),
		type: 'complex',
		multiValued: true,
		subAttributes: [
			simple('value', 'The group’s id.', { mutability: 'readOnly' }),
			simple('$ref', 'The group’s URI.', { mutability: 'readOnly' }),
			simple('display', 'The group’s displayName.', { mutability: 'readOnly' }),
			simple('type', '"direct": groups do not nest.', {
				mutability: 'readOnly'
			})
		]
	}
];

/*
 * The Group resource (RFC 7643 §4.2) as IPSIE AL SCIM §6.2.1 requires it: `displayName`, `members`, and the
 * client's `externalId`. Groups are flat, so a member is always a User.
 */
export const SCIM_GROUP_ATTRIBUTES: readonly ScimAttribute[] = [
	simple(
		'displayName',
		'The group’s name, unique in the bucket in any letter case. Relying parties receive it in the groups claim.',
		{ required: true, uniqueness: 'server' }
	),
	simple(
		'externalId',
		'The identifier the directory assigned. Unique within the provisioning connection (RFC 7643 §3.1).',
		{ caseExact: true }
	),
	{
		...simple(
			'members',
			'The group’s members — users of this connection. At least 50 may be added or removed in one PATCH.'
		),
		type: 'complex',
		multiValued: true,
		subAttributes: [
			simple('value', 'The member’s user id.', { caseExact: true }),
			simple('$ref', 'The member’s URI.', { mutability: 'readOnly' }),
			simple('type', 'Always "User": groups do not nest.'),
			simple('display', 'Accepted and not stored.', { mutability: 'readOnly' })
		]
	}
];

export const SCIM_ENTERPRISE_ATTRIBUTES: readonly ScimAttribute[] = [
	simple('employeeNumber', 'The employee number.'),
	simple('costCenter', 'The cost center.'),
	simple('organization', 'The organization.'),
	simple('division', 'The division.'),
	simple('department', 'The department.'),
	{
		...simple('manager', 'The user’s manager.'),
		type: 'complex',
		subAttributes: [simple('value', 'The manager’s id.')]
	}
];

/* Attributes every resource carries that no schema lists (RFC 7643 §3.1); a request may not change them. */
export const SCIM_READ_ONLY_ATTRIBUTES: readonly string[] = [
	'id',
	'meta',
	'schemas'
];
