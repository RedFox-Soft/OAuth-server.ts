import { guideSituation } from '../consts/situation_guide.js';

/*
 * Where a link from the site goes (`/admin/start?s=<id>` or `?e=<id>`). Pure, and importing only the declaration,
 * because the console's browser bundle loads it.
 */

export interface StartProject {
	id: string;
	name: string;
	/* The reader may change this project: the guide's buttons would be open to them. */
	editable: boolean;
	/* The administrators' project, which no guide answer sets up. */
	system: boolean;
}

export type StartDestination =
	| { kind: 'go'; href: string }
	/* A real answer, but no project to set it up in: a new account on FoxAuth Cloud has none yet. */
	| { kind: 'noProject'; href: string }
	| { kind: 'pick'; projects: { id: string; name: string; href: string }[] };

const PROJECTS = '/admin/projects';

/*
 * An unknown answer is not guessed at: the guide would show its default, which is not what the link promised.
 * The enterprise answer wins when both are named, as in the guide itself.
 */
function chosenParam(query: URLSearchParams): string | null {
	for (const [key, tab] of [
		['e', 'enterprise'],
		['s', 'product']
	] as const) {
		const id = query.get(key);
		if (id !== null && guideSituation(id)?.tab === tab) {
			return `${key}=${encodeURIComponent(id)}`;
		}
	}
	return null;
}

export function startDestination(
	query: URLSearchParams,
	projects: readonly StartProject[]
): StartDestination {
	const param = chosenParam(query);
	const offered = projects.filter((p) => p.editable && !p.system);
	if (param === null) return { kind: 'go', href: PROJECTS };
	if (offered.length === 0) return { kind: 'noProject', href: PROJECTS };
	const hrefOf = (id: string) =>
		`${PROJECTS}/${encodeURIComponent(id)}/guide?${param}`;
	if (offered.length === 1) return { kind: 'go', href: hrefOf(offered[0].id) };
	return {
		kind: 'pick',
		projects: offered.map((p) => ({
			id: p.id,
			name: p.name,
			href: hrefOf(p.id)
		}))
	};
}
