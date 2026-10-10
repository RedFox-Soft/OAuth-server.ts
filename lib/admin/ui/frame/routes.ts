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
	| 'projects'
	| 'project.clients'
	| 'project.resources'
	| 'buckets'
	| 'bucket.users'
	| 'bucket.userGroups'
	| 'bucket.providers'
	| 'bucket.provisioning'
	| 'bucket.keys'
	| 'bucket.activity'
	| 'groups'
	| 'audit'
	| 'administrators'
	| 'usage'
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
	{ key: 'projects', pattern: ['projects'], section: 'projects' },
	{
		key: 'project.clients',
		pattern: ['projects', ':project', 'clients'],
		section: 'projects',
		area: 'Clients'
	},
	{
		key: 'project.resources',
		pattern: ['projects', ':project', 'resources'],
		section: 'projects',
		area: 'Resources'
	},
	{ key: 'buckets', pattern: ['buckets'], section: 'buckets' },
	{
		key: 'bucket.users',
		pattern: ['buckets', ':bucket', 'users'],
		section: 'buckets',
		area: 'Users'
	},
	{
		key: 'bucket.userGroups',
		pattern: ['buckets', ':bucket', 'user-groups'],
		section: 'buckets',
		area: 'User groups'
	},
	{
		key: 'bucket.providers',
		pattern: ['buckets', ':bucket', 'identity-providers'],
		section: 'buckets',
		area: 'Identity providers'
	},
	{
		key: 'bucket.provisioning',
		pattern: ['buckets', ':bucket', 'provisioning'],
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
	{ key: 'groups', pattern: ['groups'], section: 'groups' },
	{ key: 'audit', pattern: ['audit'], section: 'audit' },
	{
		key: 'administrators',
		pattern: ['administrators'],
		section: 'administrators',
		instance: true
	},
	{ key: 'usage', pattern: ['usage'], section: 'usage', instance: true },
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
 * Addresses that stand for another one. The bare entity opens its first area — a bucket's users until it
 * has an overview of its own — and the bare console opens Projects. Kept apart from the table above so a
 * redirect never has a page that could drift from the page it names.
 */
const REDIRECTS: readonly {
	readonly pattern: readonly string[];
	readonly to: (params: Partial<Record<string, string>>) => string;
}[] = [
	{ pattern: [], to: () => '/admin/projects' },
	{
		pattern: ['projects', ':project'],
		to: (p) => `/admin/projects/${encodeURIComponent(p.project ?? '')}/clients`
	},
	{
		pattern: ['buckets', ':bucket'],
		to: (p) => `/admin/buckets/${encodeURIComponent(p.bucket ?? '')}/users`
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
	projects: 'Projects',
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

export function bucketHref(bucketId: string, area = 'users'): string {
	return `/admin/buckets/${encodeURIComponent(bucketId)}/${area}`;
}

export function projectHref(projectId: string, area = 'clients'): string {
	return `/admin/projects/${encodeURIComponent(projectId)}/${area}`;
}
