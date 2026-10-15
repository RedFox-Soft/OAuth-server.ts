/*
 * Every address the console answers, in one table both sides read: the server, to render the right page
 * on the first request and to answer 404 for an address no page has; the browser, to choose the page
 * and its breadcrumb. Two copies of this list is how a link starts rendering one page on the server and
 * another after hydration, so there is one, and it imports nothing but types.
 *
 * Paths carry ids, never names, so renaming something never breaks a link to it. Search, filters, sort,
 * page and month live in the query string, which this table does not describe.
 */

export type Section =
	| 'buckets'
	| 'groups'
	| 'audit'
	| 'administrators'
	| 'usage'
	| 'settings'
	| 'keys'
	| 'agent-access'
	| 'faults';

export type PageKey =
	| 'buckets'
	| 'bucket.overview'
	| 'bucket.applications'
	| 'bucket.apis'
	| 'bucket.users'
	| 'bucket.user'
	| 'bucket.user.signIn'
	| 'bucket.user.groups'
	| 'bucket.user.activity'
	| 'bucket.userGroups'
	| 'bucket.userGroup'
	| 'bucket.signIn'
	| 'bucket.providers'
	| 'bucket.provider'
	| 'bucket.provisioning'
	| 'bucket.connection'
	| 'bucket.connection.setup'
	| 'bucket.connection.settings'
	| 'bucket.keys'
	| 'bucket.activity'
	| 'bucket.settings'
	| 'groups'
	| 'group'
	| 'audit'
	| 'administrators'
	| 'administrators.signIn'
	| 'administrators.providers'
	| 'administrators.provider'
	| 'administrators.activity'
	| 'administrators.settings'
	| 'usage'
	| 'usage.bucket'
	| 'settings'
	| 'keys'
	| 'agentAccess'
	| 'faults'
	| 'acceptInvitation';

interface RouteSpec {
	readonly key: PageKey;
	/* Segments after `/admin`; a segment starting with `:` is a parameter. */
	readonly pattern: readonly string[];
	readonly section: Section | null;
	/* Only a super administrator may open it; anyone else is told so rather than shown another page. */
	readonly instance?: boolean;
	/* Reached without a session: the invitation link a person follows from their mail. */
	readonly public?: boolean;
	/* The last breadcrumb, when the page is an area of an entity. */
	readonly area?: string;
}

export const ROUTES: readonly RouteSpec[] = [
	{ key: 'buckets', pattern: ['buckets'], section: 'buckets' },
	/* A bucket's bare address is its Overview (specs/081): a link that names the bucket lands there. */
	{
		key: 'bucket.overview',
		pattern: ['buckets', ':bucket'],
		section: 'buckets',
		area: 'Overview'
	},
	/*
	 * What the bucket holds besides its people (specs/099): its applications (OAuth clients) and its APIs
	 * (declared protected resources), each for its whole life.
	 */
	{
		key: 'bucket.applications',
		pattern: ['buckets', ':bucket', 'applications'],
		section: 'buckets',
		area: 'Applications'
	},
	{
		key: 'bucket.apis',
		pattern: ['buckets', ':bucket', 'apis'],
		section: 'buckets',
		area: 'APIs'
	},
	{
		key: 'bucket.users',
		pattern: ['buckets', ':bucket', 'users'],
		section: 'buckets',
		area: 'Users'
	},
	/* One person in a bucket (specs/082); the bare address is their Profile. */
	{
		key: 'bucket.user',
		pattern: ['buckets', ':bucket', 'users', ':user'],
		section: 'buckets',
		area: 'Profile'
	},
	{
		key: 'bucket.user.signIn',
		pattern: ['buckets', ':bucket', 'users', ':user', 'sign-in-methods'],
		section: 'buckets',
		area: 'Sign-in methods'
	},
	{
		key: 'bucket.user.groups',
		pattern: ['buckets', ':bucket', 'users', ':user', 'groups'],
		section: 'buckets',
		area: 'Groups'
	},
	{
		key: 'bucket.user.activity',
		pattern: ['buckets', ':bucket', 'users', ':user', 'activity'],
		section: 'buckets',
		area: 'Activity'
	},
	{
		key: 'bucket.userGroups',
		pattern: ['buckets', ':bucket', 'user-groups'],
		section: 'buckets',
		area: 'User groups'
	},
	/* One group of people (specs/084): its members, its name, and who keeps it. */
	{
		key: 'bucket.userGroup',
		pattern: ['buckets', ':bucket', 'user-groups', ':group'],
		section: 'buckets',
		area: 'User groups'
	},
	/* How people get in (specs/083): its own address, between who is in the bucket and who vouches for them. */
	{
		key: 'bucket.signIn',
		pattern: ['buckets', ':bucket', 'sign-in'],
		section: 'buckets',
		area: 'Sign-in'
	},
	{
		key: 'bucket.providers',
		pattern: ['buckets', ':bucket', 'identity-providers'],
		section: 'buckets',
		area: 'Identity providers'
	},
	/* One identity provider (specs/084): everything about it after it is connected. */
	{
		key: 'bucket.provider',
		pattern: ['buckets', ':bucket', 'identity-providers', ':provider'],
		section: 'buckets',
		area: 'Identity providers'
	},
	{
		key: 'bucket.provisioning',
		pattern: ['buckets', ':bucket', 'provisioning'],
		section: 'buckets',
		area: 'Provisioning'
	},
	/*
	 * One provisioning connection (specs/084); the bare address is its Overview, the one the hold email links
	 * to, so it must stay stable.
	 */
	{
		key: 'bucket.connection',
		pattern: ['buckets', ':bucket', 'provisioning', ':connection'],
		section: 'buckets',
		area: 'Provisioning'
	},
	{
		key: 'bucket.connection.setup',
		pattern: [
			'buckets',
			':bucket',
			'provisioning',
			':connection',
			'directory-setup'
		],
		section: 'buckets',
		area: 'Provisioning'
	},
	{
		key: 'bucket.connection.settings',
		pattern: ['buckets', ':bucket', 'provisioning', ':connection', 'settings'],
		section: 'buckets',
		area: 'Provisioning'
	},
	{
		key: 'bucket.keys',
		pattern: ['buckets', ':bucket', 'keys'],
		section: 'buckets',
		area: 'Signing keys'
	},
	{
		key: 'bucket.activity',
		pattern: ['buckets', ':bucket', 'activity'],
		section: 'buckets',
		area: 'Activity'
	},
	{
		key: 'bucket.settings',
		pattern: ['buckets', ':bucket', 'settings'],
		section: 'buckets',
		area: 'Settings'
	},
	{ key: 'groups', pattern: ['groups'], section: 'groups' },
	/* One administrator group (specs/085): its members, invitations and what it owns. */
	{ key: 'group', pattern: ['groups', ':group'], section: 'groups' },
	{ key: 'audit', pattern: ['audit'], section: 'audit' },
	{
		key: 'administrators',
		pattern: ['administrators'],
		section: 'administrators',
		instance: true
	},
	/* The console's own bucket, at home with its accounts (specs/083). */
	{
		key: 'administrators.signIn',
		pattern: ['administrators', 'sign-in'],
		section: 'administrators',
		instance: true,
		area: 'Sign-in'
	},
	{
		key: 'administrators.providers',
		pattern: ['administrators', 'identity-providers'],
		section: 'administrators',
		instance: true,
		area: 'Identity providers'
	},
	{
		key: 'administrators.provider',
		pattern: ['administrators', 'identity-providers', ':provider'],
		section: 'administrators',
		instance: true,
		area: 'Identity providers'
	},
	{
		key: 'administrators.activity',
		pattern: ['administrators', 'activity'],
		section: 'administrators',
		instance: true,
		area: 'Activity'
	},
	{
		key: 'administrators.settings',
		pattern: ['administrators', 'settings'],
		section: 'administrators',
		instance: true,
		area: 'Settings'
	},
	/* Every administrator's since specs/091, over the buckets their groups own; the server does the narrowing. */
	{ key: 'usage', pattern: ['usage'], section: 'usage' },
	/* A deleted bucket's history (specs/086): a tombstone belongs to Usage, not to Buckets. */
	{
		key: 'usage.bucket',
		pattern: ['usage', 'buckets', ':bucket'],
		section: 'usage'
	},
	{
		key: 'settings',
		pattern: ['settings'],
		section: 'settings',
		instance: true
	},
	{
		key: 'settings',
		pattern: ['settings', ':pane'],
		section: 'settings',
		instance: true
	},
	{ key: 'keys', pattern: ['keys'], section: 'keys', instance: true },
	{
		key: 'agentAccess',
		pattern: ['agent-access'],
		section: 'agent-access',
		instance: true
	},
	{ key: 'faults', pattern: ['faults'], section: 'faults', instance: true },
	{
		key: 'faults',
		pattern: ['faults', ':reference'],
		section: 'faults',
		instance: true
	},
	{
		key: 'acceptInvitation',
		pattern: ['accept-invitation'],
		section: null,
		public: true
	}
];

/*
 * Addresses that stand for another one. The bare console opens Buckets; a bucket's bare address is a page of
 * its own, its Overview. Kept apart from the table above so a
 * redirect never has a page that could drift from the page it names. Checked before the table, so the
 * literal administrators' bucket below wins over the Overview pattern.
 */
const REDIRECTS: readonly {
	readonly pattern: readonly string[];
	readonly to: (params: Partial<Record<string, string>>) => string;
}[] = [
	{ pattern: [], to: () => '/admin/buckets' },
	/*
	 * The administrators' bucket lives on the Administrators page (specs/083): every address it had as a bucket
	 * leads to the matching tab there, so an old link still lands somewhere that means the same. Its id is
	 * written out rather than imported, so this module keeps importing nothing but types.
	 */
	{ pattern: ['buckets', 'admin'], to: () => '/admin/administrators/sign-in' },
	...(
		[
			['sign-in', 'sign-in'],
			['identity-providers', 'identity-providers'],
			['activity', 'activity'],
			['settings', 'settings'],
			['users', ''],
			// Areas it never had as a bucket land on its accounts rather than on a refusal.
			['user-groups', ''],
			['provisioning', ''],
			['keys', '']
		] as const
	).map(([from, to]) => ({
		pattern: ['buckets', 'admin', from],
		to: () => `/admin/administrators${to ? `/${to}` : ''}`
	})),
	{
		pattern: ['buckets', 'admin', 'identity-providers', ':provider'],
		to: (p) =>
			`/admin/administrators/identity-providers/${encodeURIComponent(p.provider ?? '')}`
	}
];

export interface Route {
	readonly key: PageKey;
	readonly params: Readonly<Partial<Record<string, string>>>;
	readonly section: Section | null;
	readonly instance: boolean;
	readonly public: boolean;
	readonly area: string | null;
}

export type Resolved =
	| { readonly kind: 'page'; readonly route: Route }
	| { readonly kind: 'redirect'; readonly to: string }
	| { readonly kind: 'none' };

function segmentsOf(pathname: string): string[] | null {
	if (pathname !== '/admin' && !pathname.startsWith('/admin/')) return null;
	const rest = pathname.slice('/admin'.length);
	const parts = rest.split('/').filter((part) => part !== '');
	try {
		return parts.map((part) => decodeURIComponent(part));
	} catch {
		// A malformed escape is an address no page has, not a fault.
		return null;
	}
}

function bind(
	pattern: readonly string[],
	parts: readonly string[]
): Record<string, string> | null {
	if (pattern.length !== parts.length) return null;
	const params: Record<string, string> = {};
	for (let i = 0; i < pattern.length; i += 1) {
		const want = pattern[i] ?? '';
		const got = parts[i] ?? '';
		if (want.startsWith(':')) params[want.slice(1)] = got;
		else if (want !== got) return null;
	}
	return params;
}

/* The page, the address it stands for, or nothing — `pathname` without the query string. */
export function resolveAddress(pathname: string): Resolved {
	const parts = segmentsOf(pathname);
	if (!parts) return { kind: 'none' };
	for (const redirect of REDIRECTS) {
		const params = bind(redirect.pattern, parts);
		if (params) return { kind: 'redirect', to: redirect.to(params) };
	}
	for (const spec of ROUTES) {
		const params = bind(spec.pattern, parts);
		if (params) {
			return {
				kind: 'page',
				route: {
					key: spec.key,
					params,
					section: spec.section,
					instance: spec.instance === true,
					public: spec.public === true,
					area: spec.area ?? null
				}
			};
		}
	}
	return { kind: 'none' };
}

export const SECTION_LABELS: Readonly<Record<Section, string>> = {
	buckets: 'Buckets',
	groups: 'Groups',
	audit: 'Audit',
	administrators: 'Administrators',
	usage: 'Usage',
	settings: 'Settings',
	keys: 'Keys',
	'agent-access': 'Agent access',
	faults: 'Faults'
};

export function sectionHref(section: Section): string {
	return `/admin/${section}`;
}

/* A bucket's address; without an area, its Overview. */
export function bucketHref(bucketId: string, area?: string): string {
	const base = `/admin/buckets/${encodeURIComponent(bucketId)}`;
	return area ? `${base}/${area}` : base;
}

/* One person in a bucket; without an area, their Profile. */
export function userHref(
	bucketId: string,
	userId: string,
	area?: string
): string {
	const base = `${bucketHref(bucketId, 'users')}/${encodeURIComponent(userId)}`;
	return area ? `${base}/${area}` : base;
}

/*
 * An identity provider's page. The console's own bucket keeps its providers under Administrators, so the
 * address depends on the bucket and every caller asks here rather than spelling it.
 */
export function providerHref(bucketId: string, providerId: string): string {
	const base =
		bucketId === 'admin'
			? '/admin/administrators/identity-providers'
			: bucketHref(bucketId, 'identity-providers');
	return `${base}/${encodeURIComponent(providerId)}`;
}

/* A provisioning connection; without an area, its Overview. */
export function connectionHref(
	bucketId: string,
	connectionId: string,
	area?: 'directory-setup' | 'settings'
): string {
	const base = `${bucketHref(bucketId, 'provisioning')}/${encodeURIComponent(connectionId)}`;
	return area ? `${base}/${area}` : base;
}

export function userGroupHref(bucketId: string, groupId: string): string {
	return `${bucketHref(bucketId, 'user-groups')}/${encodeURIComponent(groupId)}`;
}

export function groupHref(groupId: string): string {
	return `/admin/groups/${encodeURIComponent(groupId)}`;
}

export function usageBucketHref(bucketId: string, month?: string): string {
	const base = `/admin/usage/buckets/${encodeURIComponent(bucketId)}`;
	return month ? `${base}?month=${encodeURIComponent(month)}` : base;
}
