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
	| 'projects'
	| 'teams'
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
	| 'bucket.application'
	| 'bucket.application.settings'
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
	{ key: 'buckets', pattern: ['projects'], section: 'projects' },
	/* A project's bare address is its Overview (specs/081): a link that names the project lands there. */
	{
		key: 'bucket.overview',
		pattern: ['projects', ':project'],
		section: 'projects',
		area: 'Overview'
	},
	/*
	 * What the bucket holds besides its people (specs/099): its applications (OAuth clients) and its APIs
	 * (declared protected resources), each for its whole life.
	 */
	{
		key: 'bucket.applications',
		pattern: ['projects', ':project', 'applications'],
		section: 'projects',
		area: 'Applications'
	},
	/*
	 * One application (spec 107): the bare address is its Connect tab, the place a developer comes back to for its
	 * values; Settings holds everything else about it.
	 */
	{
		key: 'bucket.application',
		pattern: ['projects', ':project', 'applications', ':client'],
		section: 'projects',
		area: 'Applications'
	},
	{
		key: 'bucket.application.settings',
		pattern: ['projects', ':project', 'applications', ':client', 'settings'],
		section: 'projects',
		area: 'Applications'
	},
	{
		key: 'bucket.apis',
		pattern: ['projects', ':project', 'apis'],
		section: 'projects',
		area: 'APIs'
	},
	{
		key: 'bucket.users',
		pattern: ['projects', ':project', 'users'],
		section: 'projects',
		area: 'Users'
	},
	/* One person in a bucket (specs/082); the bare address is their Profile. */
	{
		key: 'bucket.user',
		pattern: ['projects', ':project', 'users', ':user'],
		section: 'projects',
		area: 'Profile'
	},
	{
		key: 'bucket.user.signIn',
		pattern: ['projects', ':project', 'users', ':user', 'sign-in-methods'],
		section: 'projects',
		area: 'Sign-in methods'
	},
	{
		key: 'bucket.user.groups',
		pattern: ['projects', ':project', 'users', ':user', 'groups'],
		section: 'projects',
		area: 'Groups'
	},
	{
		key: 'bucket.user.activity',
		pattern: ['projects', ':project', 'users', ':user', 'activity'],
		section: 'projects',
		area: 'Activity'
	},
	{
		key: 'bucket.userGroups',
		pattern: ['projects', ':project', 'groups'],
		section: 'projects',
		area: 'Groups'
	},
	/* One group of people (specs/084): its members, its name, and who keeps it. */
	{
		key: 'bucket.userGroup',
		pattern: ['projects', ':project', 'groups', ':group'],
		section: 'projects',
		area: 'Groups'
	},
	/* How people get in (specs/083): its own address, between who is in the bucket and who vouches for them. */
	{
		key: 'bucket.signIn',
		pattern: ['projects', ':project', 'sign-in'],
		section: 'projects',
		area: 'Sign-in'
	},
	{
		key: 'bucket.providers',
		pattern: ['projects', ':project', 'identity-providers'],
		section: 'projects',
		area: 'Identity providers'
	},
	/* One identity provider (specs/084): everything about it after it is connected. */
	{
		key: 'bucket.provider',
		pattern: ['projects', ':project', 'identity-providers', ':provider'],
		section: 'projects',
		area: 'Identity providers'
	},
	{
		key: 'bucket.provisioning',
		pattern: ['projects', ':project', 'provisioning'],
		section: 'projects',
		area: 'Provisioning'
	},
	/*
	 * One provisioning connection (specs/084); the bare address is its Overview, the one the hold email links
	 * to, so it must stay stable.
	 */
	{
		key: 'bucket.connection',
		pattern: ['projects', ':project', 'provisioning', ':connection'],
		section: 'projects',
		area: 'Provisioning'
	},
	{
		key: 'bucket.connection.setup',
		pattern: [
			'projects',
			':project',
			'provisioning',
			':connection',
			'directory-setup'
		],
		section: 'projects',
		area: 'Provisioning'
	},
	{
		key: 'bucket.connection.settings',
		pattern: [
			'projects',
			':project',
			'provisioning',
			':connection',
			'settings'
		],
		section: 'projects',
		area: 'Provisioning'
	},
	{
		key: 'bucket.keys',
		pattern: ['projects', ':project', 'keys'],
		section: 'projects',
		area: 'Signing keys'
	},
	{
		key: 'bucket.activity',
		pattern: ['projects', ':project', 'activity'],
		section: 'projects',
		area: 'Activity'
	},
	{
		key: 'bucket.settings',
		pattern: ['projects', ':project', 'settings'],
		section: 'projects',
		area: 'Settings'
	},
	{ key: 'groups', pattern: ['teams'], section: 'teams' },
	/* One team (specs/085): its members, invitations and what it owns. */
	{ key: 'group', pattern: ['teams', ':team'], section: 'teams' },
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
	/* Every administrator's since specs/091, over the projects their teams own; the server does the narrowing. */
	{ key: 'usage', pattern: ['usage'], section: 'usage' },
	/* A deleted project's history (specs/086): a tombstone belongs to Usage, not to Projects. */
	{
		key: 'usage.bucket',
		pattern: ['usage', 'projects', ':project'],
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
 * Addresses that stand for another one. The bare console opens Projects; a project's bare address is a page
 * of its own, its Overview. Kept apart from the table above so a redirect never has a page that could drift
 * from the page it names. Checked before the table, so the literal administrators' project below wins over
 * the Overview pattern.
 */
interface Redirect {
	readonly pattern: readonly string[];
	readonly to: (params: Partial<Record<string, string>>) => string;
}

/*
 * The administrators' bucket lives on the Administrators page (specs/083): every address it had as a project
 * leads to the matching tab there, so an old link still lands somewhere that means the same. Its id is
 * written out rather than imported, so this module keeps importing nothing but types. Spelled under both the
 * address it had before spec 100 and the one it would have now, so neither opens it as a project.
 */
function administratorsRedirects(
	root: 'buckets' | 'projects',
	groupsArea: 'user-groups' | 'groups'
): Redirect[] {
	return [
		{ pattern: [root, 'admin'], to: () => '/admin/administrators/sign-in' },
		...(
			[
				['sign-in', 'sign-in'],
				['identity-providers', 'identity-providers'],
				['activity', 'activity'],
				['settings', 'settings'],
				['users', ''],
				// Areas it never had as a project land on its accounts rather than on a refusal.
				[groupsArea, ''],
				['provisioning', ''],
				['keys', '']
			] as const
		).map(([from, to]) => ({
			pattern: [root, 'admin', from],
			to: () => `/admin/administrators${to ? `/${to}` : ''}`
		})),
		{
			pattern: [root, 'admin', 'identity-providers', ':provider'],
			to: (p) =>
				`/admin/administrators/identity-providers/${encodeURIComponent(p.provider ?? '')}`
		}
	];
}

/*
 * The address a page had before spec 100 named buckets, administrator groups and user groups by their
 * storage names. Emailed held-connection links and bookmarks use the old addresses, so each one still opens
 * its page: derived from the table rather than listed, so no page can gain an address its old one misses.
 */
function formerPattern(pattern: readonly string[]): string[] | null {
	const [root, ...rest] = pattern;
	if (root === 'projects') {
		return [
			'buckets',
			...rest.map((segment, i) =>
				i === 1 && segment === 'groups' ? 'user-groups' : segment
			)
		];
	}
	if (root === 'teams') return ['groups', ...rest];
	if (root === 'usage' && rest[0] === 'projects')
		return ['usage', 'buckets', ...rest.slice(1)];
	return null;
}

function addressOf(
	pattern: readonly string[],
	params: Partial<Record<string, string>>
): string {
	return `/admin/${pattern
		.map((segment) =>
			segment.startsWith(':')
				? encodeURIComponent(params[segment.slice(1)] ?? '')
				: segment
		)
		.join('/')}`;
}

const REDIRECTS: readonly Redirect[] = [
	{ pattern: [], to: () => '/admin/projects' },
	...administratorsRedirects('buckets', 'user-groups'),
	...administratorsRedirects('projects', 'groups'),
	...ROUTES.flatMap((spec) => {
		const former = formerPattern(spec.pattern);
		return former
			? [
					{
						pattern: former,
						to: (p: Partial<Record<string, string>>) =>
							addressOf(spec.pattern, p)
					}
				]
			: [];
	})
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
	projects: 'Projects',
	teams: 'Teams',
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

/* A project's address; without an area, its Overview. */
export function bucketHref(bucketId: string, area?: string): string {
	const base = `/admin/projects/${encodeURIComponent(bucketId)}`;
	return area ? `${base}/${area}` : base;
}

/* One person in a project; without an area, their Profile. */
export function userHref(
	bucketId: string,
	userId: string,
	area?: string
): string {
	const base = `${bucketHref(bucketId, 'users')}/${encodeURIComponent(userId)}`;
	return area ? `${base}/${area}` : base;
}

/*
 * An identity provider's page. The console's own project keeps its providers under Administrators, so the
 * address depends on the project and every caller asks here rather than spelling it.
 */
export function providerHref(bucketId: string, providerId: string): string {
	const base =
		bucketId === 'admin'
			? '/admin/administrators/identity-providers'
			: bucketHref(bucketId, 'identity-providers');
	return `${base}/${encodeURIComponent(providerId)}`;
}

/* An application's page; without a tab, its Connect tab. */
export function applicationHref(
	bucketId: string,
	clientId: string,
	tab?: 'settings'
): string {
	const base = `${bucketHref(bucketId, 'applications')}/${encodeURIComponent(clientId)}`;
	return tab ? `${base}/${tab}` : base;
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
	return `${bucketHref(bucketId, 'groups')}/${encodeURIComponent(groupId)}`;
}

export function groupHref(groupId: string): string {
	return `/admin/teams/${encodeURIComponent(groupId)}`;
}

export function usageBucketHref(bucketId: string, month?: string): string {
	const base = `/admin/usage/projects/${encodeURIComponent(bucketId)}`;
	return month ? `${base}?month=${encodeURIComponent(month)}` : base;
}
