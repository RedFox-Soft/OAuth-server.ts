import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import {
	GUIDE_QUESTIONS,
	GUIDE_SITUATIONS,
	guideSituation,
	type GuideSituation
} from 'lib/consts/situation_guide.ts';
import { GUIDE_PARTS } from 'lib/situation_guide/parts.ts';
import { sceneOf, type Scene } from 'lib/situation_guide/scene.ts';
import {
	GUIDE_ACTOR_PARTS,
	optionPartsOf
} from 'lib/situation_guide/options.ts';

function situation(id: string): GuideSituation {
	const found = guideSituation(id);
	if (!found) throw new Error(`no situation ${id}`);
	return found;
}

function roleOf(scene: Scene, lane: string) {
	return scene.nodes.find((node) => node.lane === lane)?.role;
}

function joins(scene: Scene, a: string, b: string) {
	return scene.links.find(
		(link) =>
			(link.from === a && link.to === b) || (link.from === b && link.to === a)
	);
}

/**
 * @proves every guide answer shows a reader their problem and its fix in a picture, and the picture never shows
 * FoxAuth carrying a call it does not carry
 */
describe('the guide pictures', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('can draw every situation, with its problem marked on a part the picture shows', () => {
		for (const s of GUIDE_SITUATIONS) {
			expect(s.lanes.map((lane) => lane.id)).toContain(s.problem.at);
			expect(s.problem.caption.trim()).not.toBe('');
			expect(s.fixCaption.trim()).not.toBe('');
			for (const lane of s.lanes) expect(GUIDE_PARTS[lane.part]).toBeDefined();
			const { problem } = sceneOf(s);
			expect(problem.mark).toEqual({ at: s.problem.at, kind: s.problem.mark });
			expect(problem.nodes.map((node) => node.lane)).toContain(s.problem.at);
			expect(problem.nodes.some((node) => node.role === 'fox')).toBe(false);
			if (s.problem.lanes) {
				expect(problem.nodes.map((node) => node.lane).sort()).toEqual(
					[...s.problem.lanes].sort()
				);
			}
		}
	});

	it('never links FoxAuth to a resource, in any situation', () => {
		/* In the administrative MCP the resource is FoxAuth itself. */
		for (const s of GUIDE_SITUATIONS.filter((s) => s.id !== 'adminmcp')) {
			const { solution } = sceneOf(s);
			for (const link of solution.links) {
				const roles = [roleOf(solution, link.from), roleOf(solution, link.to)];
				expect(roles.includes('fox') && roles.includes('resource')).toBe(false);
			}
		}
	});

	it('draws FoxAuth beside the path, handing the token to the client that calls the resource directly', () => {
		for (const id of [
			'spa',
			'server',
			'native',
			'device',
			'service',
			'mcp',
			'signup',
			'behindproxy'
		]) {
			const { solution } = sceneOf(situation(id));
			const isFox = solution.nodes.map((node) => node.role === 'fox');
			expect(isFox.includes(true)).toBe(true);
			expect(isFox.slice(isFox.indexOf(true))).not.toContain(false);
		}
		for (const id of ['spa', 'server', 'native', 'device', 'service', 'mcp']) {
			const { solution } = sceneOf(situation(id));
			const tokens = solution.links.filter(
				(link) => link.kind === 'token' && roleOf(solution, link.from) === 'fox'
			);
			expect(tokens.length).toBeGreaterThan(0);
			for (const resource of solution.nodes.filter(
				(node) => node.role === 'resource'
			)) {
				const call = tokens
					.map((token) => joins(solution, token.to, resource.lane))
					.find(Boolean);
				expect(call).toMatchObject({ to: resource.lane, kind: 'direct' });
			}
		}
		const spa = sceneOf(situation('spa')).solution;
		expect(joins(spa, 'spa', 'api')).toMatchObject({
			from: 'spa',
			to: 'api',
			kind: 'direct'
		});
	});

	it('draws a web app behind a proxy with the proxy as its own part that asks FoxAuth, and FoxAuth never linked to the app', () => {
		const { solution } = sceneOf(situation('behindproxy'));
		const proxy = solution.nodes.find((node) => node.role === 'proxy');
		expect(proxy?.part).toBe('proxy');
		expect(solution.placement).toBe('beside');
		const fox = solution.nodes.find((node) => node.role === 'fox');
		expect(fox).toBeDefined();
		expect(joins(solution, fox?.lane ?? '', proxy?.lane ?? '')).toBeDefined();
		for (const app of solution.nodes.filter(
			(node) => node.role === 'resource'
		)) {
			expect(joins(solution, fox?.lane ?? '', app.lane)).toBeUndefined();
			expect(joins(solution, proxy?.lane ?? '', app.lane)).toMatchObject({
				kind: 'direct'
			});
		}
		expect(solution.nodes.some((node) => node.role === 'resource')).toBe(true);
	});

	it('draws FoxAuth between the two parties where it carries the exchange', () => {
		for (const [id, a, b] of [
			['okta', 'webapp', 'idp'],
			['connected', 'agent', 'google']
		] as const) {
			const { solution } = sceneOf(situation(id));
			const at = (lane: string) =>
				solution.nodes.findIndex((node) => node.lane === lane);
			expect(at('fox')).toBeGreaterThan(at(a));
			expect(at('fox')).toBeLessThan(at(b));
			expect(joins(solution, a, 'fox')).toBeDefined();
			expect(joins(solution, 'fox', b)).toBeDefined();
		}
	});

	it('names, as what usually comes next, a real situation of the same tab', () => {
		for (const s of GUIDE_SITUATIONS) {
			if (!s.next) continue;
			expect(s.next).not.toBe(s.id);
			expect(guideSituation(s.next)?.tab).toBe(s.tab);
		}
	});
});

/**
 * @proves every guide picture reaches the console and the site already laid out, so both draw FoxAuth in the same
 * place and neither can put it on the path between a client and its resource
 */
describe('the guide pictures, laid out', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('places every node of every picture exactly once, the row in drawing order', () => {
		for (const s of GUIDE_SITUATIONS) {
			for (const scene of Object.values(sceneOf(s))) {
				const lanes = scene.nodes.map((node) => node.lane);
				expect([...scene.row, ...scene.above]).toEqual(lanes);
				if (scene.placement === 'middle') expect(scene.above).toEqual([]);
			}
		}
	});

	it('keeps FoxAuth off the row wherever it stands beside the path, so the client calls its resource along the row', () => {
		const beside = GUIDE_SITUATIONS.map((s) => sceneOf(s).solution).filter(
			(scene) => scene.placement === 'beside'
		);
		expect(beside.length).toBeGreaterThan(0);
		for (const scene of beside) {
			for (const lane of scene.row) expect(roleOf(scene, lane)).not.toBe('fox');
			expect(scene.above.map((lane) => roleOf(scene, lane))).toEqual(['fox']);
			for (const link of scene.links) {
				const roles = [roleOf(scene, link.from), roleOf(scene, link.to)];
				if (roles.includes('client') && roles.includes('resource')) {
					expect(scene.row).toContain(link.from);
					expect(scene.row).toContain(link.to);
				}
			}
		}
		for (const id of [
			'spa',
			'server',
			'mcp',
			'device',
			'service',
			'behindproxy'
		])
			expect(sceneOf(situation(id)).solution.placement).toBe('beside');
		for (const id of ['okta', 'connected'])
			expect(sceneOf(situation(id)).solution.placement).toBe('middle');
	});

	it('arcs exactly the links that would pass behind a node of the row, and never two arcs at one height where they overlap', () => {
		for (const s of GUIDE_SITUATIONS) {
			for (const scene of Object.values(sceneOf(s))) {
				const at = new Map(scene.row.map((lane, i) => [lane, i]));
				const arcs: { lo: number; hi: number; level: number }[] = [];
				for (const link of scene.links) {
					const a = at.get(link.from);
					const b = at.get(link.to);
					const skips =
						a !== undefined && b !== undefined && Math.abs(a - b) > 1;
					expect(link.arc !== undefined).toBe(skips);
					if (skips && link.arc !== undefined)
						arcs.push({
							lo: Math.min(a, b),
							hi: Math.max(a, b),
							level: link.arc
						});
				}
				for (const x of arcs)
					for (const y of arcs)
						if (x !== y && x.lo < y.hi && y.lo < x.hi)
							expect(x.level).not.toBe(y.level);
			}
		}
	});

	it('gives every option of the chooser a picture drawn from the parts', () => {
		for (const s of GUIDE_SITUATIONS) {
			const parts = optionPartsOf(s);
			expect(parts.length).toBeGreaterThan(0);
			for (const part of parts) expect(GUIDE_PARTS[part]).toBeDefined();
			if (s.ask) expect(parts).not.toContain(GUIDE_ACTOR_PARTS[s.ask.actor][0]);
		}
		for (const question of GUIDE_QUESTIONS) {
			for (const part of GUIDE_ACTOR_PARTS[question.actor])
				expect(GUIDE_PARTS[part]).toBeDefined();
		}
	});
});

/**
 * @proves the fix picture never puts its check on a party the fix refuses (the thief with a copied token, the person
 * who left) or on a party outside the reader's control
 */
describe('the check in the fix picture', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('never puts the check on a party the fix refuses', () => {
		for (const s of GUIDE_SITUATIONS) {
			const { solution } = sceneOf(s);
			if (solution.fixed === undefined) continue;
			expect(solution.fixed).toBe(s.problem.at);
			expect(solution.nodes.map((node) => node.lane)).toContain(solution.fixed);
			expect(roleOf(solution, solution.fixed)).not.toBe('outside');
			const refused = solution.links.filter(
				(link) =>
					link.kind === 'broken' &&
					(link.from === solution.fixed || link.to === solution.fixed)
			);
			expect(refused).toEqual([]);
		}
		expect(sceneOf(situation('bound')).solution.fixed).toBeUndefined();
		expect(sceneOf(situation('scim')).solution.fixed).toBeUndefined();
		expect(sceneOf(situation('spa')).solution.fixed).toBe('spa');
	});
});
