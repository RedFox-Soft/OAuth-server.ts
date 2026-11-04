import type {
	GuideActor,
	GuidePart,
	GuideSituation
} from '../consts/situation_guide.js';
import { sceneOf } from './scene.js';

/*
 * What the guide's chooser draws on its options, so the site and the console show the same small pictures and
 * neither keeps a rule of its own. Import-free beyond the scene rule and the types, like it.
 */

/* Question 1's options: each actor, with what it works at (a person at a laptop, a server on a schedule, an agent at an API). */
export const GUIDE_ACTOR_PARTS: Readonly<
	Record<GuideActor, readonly [GuidePart, GuidePart]>
> = {
	person: ['person', 'laptop'],
	program: ['server', 'clock'],
	agent: ['agent', 'api']
};

/*
 * The parts an option for this answer shows, read off the answer's own pictures rather than kept per answer: the part
 * that has the problem, and the party outside your control the fix involves, in the order the answer's lanes run. An
 * answer of question 2 leaves out the part of the actor already chosen in question 1 (every agent answer would
 * otherwise start with the agent); what is left empty is FoxAuth itself, as in the administrative MCP.
 */
export function optionPartsOf(situation: GuideSituation): GuidePart[] {
	const { problem, solution } = sceneOf(situation);
	const without = situation.ask
		? GUIDE_ACTOR_PARTS[situation.ask.actor][0]
		: undefined;
	const at = problem.nodes.find((node) => node.lane === problem.mark?.at);
	const outside = solution.nodes.find((node) => node.role === 'outside');
	const order = new Map(situation.lanes.map((lane, i) => [lane.id, i]));
	const picked = [at, outside]
		.filter((node) => node !== undefined)
		.sort((x, y) => (order.get(x.lane) ?? 0) - (order.get(y.lane) ?? 0))
		.map((node) => node.part)
		.filter((part, i, all) => part !== without && all.indexOf(part) === i);
	return picked.length > 0 ? picked : ['fox'];
}
