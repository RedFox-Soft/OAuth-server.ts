import type {
	GuideLane,
	GuidePart,
	GuideSituation,
	GuideStep,
	ProblemMark
} from '../consts/situation_guide.js';

/*
 * The two pictures of a guide answer, "Your problem" and "With FoxAuth", worked out from the situation's lanes and
 * steps by one rule, so no page keeps a picture of its own. Pure and import-free beyond the types: the console's
 * browser bundle imports it, and the docs export carries its result to the site.
 *
 * The rule is the topology the critiques settled. FoxAuth hands a token to the client and stands beside the path:
 * the client then calls its resource directly, never through FoxAuth. FoxAuth is drawn between two parties only
 * where it really carries the exchange, which is where it talks to a party outside the reader's control (another
 * provider, the company's provider or directory) as well as to someone else.
 */

export type SceneRole = 'actor' | 'client' | 'resource' | 'fox' | 'outside';

export interface SceneNode {
	lane: string;
	part: GuidePart;
	role: SceneRole;
}

export interface SceneLink {
	from: string;
	to: string;
	kind: 'direct' | 'token' | 'broken';
	/*
	 * Set when both ends are on the row but not neighbours: the link arcs over the nodes between them, at this
	 * level (1 the lowest), raised over every lower arc it overlaps so no two arcs share a height. A link without it
	 * is straight.
	 */
	arc?: number;
}

/*
 * How a scene is laid out, so every page that draws it agrees and none keeps a rule of its own; a page adds only
 * sizes.
 *
 * - `beside`: FoxAuth's one node stands above the row (`above`), over what it links to. The row is everyone else in
 *   lane order, so the client's call to its resource runs along the row and never through FoxAuth.
 * - `middle`: one row in lane order (`above` empty). FoxAuth, when drawn, stands in its place between the parties it
 *   carries the exchange for; a problem picture, which has no FoxAuth, is always this.
 */
export interface Scene {
	placement: 'beside' | 'middle';
	row: string[];
	above: string[];
	/* Nodes are in drawing order: the row, then what stands above it. */
	nodes: SceneNode[];
	links: SceneLink[];
	mark?: { at: string; kind: ProblemMark };
	/*
	 * The solution's check: the lane that had the problem, now fixed. Absent where that lane is not drawn, is outside
	 * the reader's control, or is the party the fix refuses (a broken link touches it: the thief with a copied token,
	 * the person who left), so a check never lands on someone FoxAuth turns away.
	 */
	fixed?: string;
}

const ROLE_BY_KIND: Readonly<Record<GuideLane['kind'], SceneRole>> = {
	person: 'actor',
	browser: 'client',
	app: 'client',
	agent: 'client',
	api: 'resource',
	fox: 'fox',
	outside: 'outside',
	company: 'outside'
};

const pairKey = (a: string, b: string) => (a < b ? `${a} ${b}` : `${b} ${a}`);

/*
 * Who ends up holding FoxAuth's token: whoever FoxAuth sends one to, and your own part that trades for one. A token
 * an outside party sends to FoxAuth (Google's access, in a connected service) makes it no client.
 */
function tokenHolders(s: GuideSituation, fox: ReadonlySet<string>) {
	const outside = new Set(
		s.lanes.filter((l) => ROLE_BY_KIND[l.kind] === 'outside').map((l) => l.id)
	);
	const holders = new Set<string>();
	for (const step of s.steps) {
		if (step.style !== 'token' || step.from === step.to) continue;
		if (fox.has(step.from) && !fox.has(step.to)) holders.add(step.to);
		if (fox.has(step.to) && !fox.has(step.from) && !outside.has(step.from))
			holders.add(step.from);
	}
	return holders;
}

/* The steps between two different lanes, grouped by the pair, in the order the pair first appears. */
function pairs(steps: readonly GuideStep[]) {
	const grouped = new Map<string, GuideStep[]>();
	for (const step of steps) {
		if (step.from === step.to) continue;
		const key = pairKey(step.from, step.to);
		grouped.set(key, [...(grouped.get(key) ?? []), step]);
	}
	return [...grouped.values()];
}

function linkOf(
	group: readonly GuideStep[],
	fox: ReadonlySet<string>,
	holders: ReadonlySet<string>
): SceneLink {
	const [first] = group;
	const [a, b] = [first.from, first.to];
	const foxEnd = fox.has(a) ? a : fox.has(b) ? b : undefined;
	const other = foxEnd === a ? b : a;
	if (foxEnd && holders.has(other))
		return { from: foxEnd, to: other, kind: 'token' };
	const token = group.find((step) => step.style === 'token');
	if (token) return { from: token.from, to: token.to, kind: 'token' };
	const last = group[group.length - 1];
	return {
		from: a,
		to: b,
		kind: last.style === 'refusal' ? 'broken' : 'direct'
	};
}

function nodeOf(lane: GuideLane, holders: ReadonlySet<string>): SceneNode {
	const role = ROLE_BY_KIND[lane.kind];
	return {
		lane: lane.id,
		part: lane.part,
		role: role !== 'fox' && holders.has(lane.id) ? 'client' : role
	};
}

/*
 * FoxAuth is in the middle when a party outside the reader's control sends something to it, and someone else deals
 * with it too: federation, the company's provider and directory, a connected service. FoxAuth only sending out (an
 * email to the person's inbox) leaves it beside the path.
 */
function foxInTheMiddle(
	s: GuideSituation,
	fox: ReadonlySet<string>,
	holders: ReadonlySet<string>
) {
	const outside = new Set(
		s.lanes.filter((l) => ROLE_BY_KIND[l.kind] === 'outside').map((l) => l.id)
	);
	const partners = new Set<string>();
	const senders = new Set<string>();
	for (const step of s.steps) {
		if (fox.has(step.from) && !fox.has(step.to)) partners.add(step.to);
		if (fox.has(step.to) && !fox.has(step.from)) {
			partners.add(step.from);
			senders.add(step.from);
		}
	}
	const thirdParty = [...senders].some(
		(id) => outside.has(id) && !holders.has(id)
	);
	return thirdParty && partners.size > 1;
}

/*
 * The row's arcs: a link between two row nodes that are not neighbours arcs over the ones between, the shorter arcs
 * lowest, each raised one level over every arc already placed that it overlaps.
 */
function withArcs(links: SceneLink[], row: readonly string[]): SceneLink[] {
	const at = new Map(row.map((lane, i) => [lane, i]));
	const spans = links
		.flatMap((link, index) => {
			const a = at.get(link.from);
			const b = at.get(link.to);
			if (a === undefined || b === undefined || Math.abs(a - b) <= 1) return [];
			return [{ index, lo: Math.min(a, b), hi: Math.max(a, b), level: 0 }];
		})
		.sort((x, y) => x.hi - x.lo - (y.hi - y.lo) || x.index - y.index);
	for (const [i, span] of spans.entries()) {
		const under = spans
			.slice(0, i)
			.filter((other) => other.lo < span.hi && span.lo < other.hi);
		span.level = 1 + Math.max(0, ...under.map((other) => other.level));
	}
	const level = new Map(spans.map((span) => [span.index, span.level]));
	return links.map((link, index) =>
		level.has(index) ? { ...link, arc: level.get(index) } : link
	);
}

function laidOut(
	nodes: SceneNode[],
	links: SceneLink[],
	placement: Scene['placement'],
	mark?: Scene['mark']
): Scene {
	const row = nodes
		.filter((node) => placement === 'middle' || node.role !== 'fox')
		.map((node) => node.lane);
	const above = nodes
		.filter((node) => placement === 'beside' && node.role === 'fox')
		.map((node) => node.lane);
	return {
		placement,
		row,
		above,
		nodes,
		links: withArcs(links, row),
		...(mark ? { mark } : {})
	};
}

/*
 * Without FoxAuth: the lanes the situation names for it, or else every lane but FoxAuth's less the ones that never
 * deal with anyone but FoxAuth (they have nothing to do in a world without it, as the person's phone in a device
 * sign-in), and always the lane that carries the mark. Its links are the steps between those lanes that do not
 * touch FoxAuth, and nothing is drawn that no step says.
 */
function problemScene(
	s: GuideSituation,
	fox: ReadonlySet<string>,
	holders: ReadonlySet<string>
): Scene {
	const withoutFox = s.steps.filter(
		(step) => !fox.has(step.from) && !fox.has(step.to)
	);
	const talking = new Set(withoutFox.flatMap((step) => [step.from, step.to]));
	const named: ReadonlySet<string> | undefined = s.problem.lanes
		? new Set(s.problem.lanes)
		: undefined;
	const lanes = s.lanes.filter((l) =>
		named
			? named.has(l.id)
			: !fox.has(l.id) && (l.id === s.problem.at || talking.has(l.id))
	);
	const drawn = new Set(lanes.map((l) => l.id));
	return laidOut(
		lanes.map((l) => nodeOf(l, holders)),
		pairs(
			withoutFox.filter((step) => drawn.has(step.from) && drawn.has(step.to))
		).map((group) => ({
			from: group[0].from,
			to: group[0].to,
			kind: 'direct'
		})),
		'middle',
		{ at: s.problem.at, kind: s.problem.mark }
	);
}

function solutionScene(
	s: GuideSituation,
	fox: ReadonlySet<string>,
	holders: ReadonlySet<string>
): Scene {
	/*
	 * Beside the path takes a path to stand beside: at least two other parties, and one FoxAuth node to stand over
	 * them. Otherwise (FoxAuth and one person, a team and its projects) the one row is the clearest picture.
	 */
	const others = s.lanes.filter((l) => !fox.has(l.id));
	const placement =
		!foxInTheMiddle(s, fox, holders) && fox.size === 1 && others.length >= 2
			? 'beside'
			: 'middle';
	const order =
		placement === 'beside' || !foxInTheMiddle(s, fox, holders)
			? [...others, ...s.lanes.filter((l) => fox.has(l.id))]
			: s.lanes;
	const scene = laidOut(
		order.map((l) => nodeOf(l, holders)),
		pairs(s.steps).map((group) => linkOf(group, fox, holders)),
		placement
	);
	const at = scene.nodes.find((node) => node.lane === s.problem.at);
	const refused = scene.links.some(
		(link) =>
			link.kind === 'broken' && (link.from === at?.lane || link.to === at?.lane)
	);
	return at && at.role !== 'outside' && !refused
		? { ...scene, fixed: at.lane }
		: scene;
}

export function sceneOf(s: GuideSituation): {
	problem: Scene;
	solution: Scene;
} {
	const fox = new Set(
		s.lanes.filter((l) => ROLE_BY_KIND[l.kind] === 'fox').map((l) => l.id)
	);
	const holders = tokenHolders(s, fox);
	return {
		problem: problemScene(s, fox, holders),
		solution: solutionScene(s, fox, holders)
	};
}
