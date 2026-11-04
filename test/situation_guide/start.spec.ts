import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { startDestination } from 'lib/situation_guide/start.ts';

const p = (id: string, over: Record<string, unknown> = {}) => ({
	id,
	name: `Project ${id}`,
	editable: true,
	system: false,
	...over
});
const q = (s: string) => new URLSearchParams(s);

/**
 * @proves a reader arriving from the site lands in their own project at the answer they chose
 */
describe('the console door for the site', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('goes straight to the guide when the reader has one project', () => {
		expect(startDestination(q('s=spa'), [p('p1')])).toEqual({
			kind: 'go',
			href: '/admin/projects/p1/guide?s=spa'
		});
	});

	it('asks which project when there are several, keeping the enterprise answer', () => {
		const result = startDestination(q('e=okta'), [p('p1'), p('p2')]);
		expect(result).toEqual({
			kind: 'pick',
			projects: [
				{
					id: 'p1',
					name: 'Project p1',
					href: '/admin/projects/p1/guide?e=okta'
				},
				{
					id: 'p2',
					name: 'Project p2',
					href: '/admin/projects/p2/guide?e=okta'
				}
			]
		});
	});

	it('falls back to the projects list for an unknown answer', () => {
		expect(startDestination(q('s=nope'), [p('p1')])).toEqual({
			kind: 'go',
			href: '/admin/projects'
		});
		expect(startDestination(q(''), [p('p1')])).toEqual({
			kind: 'go',
			href: '/admin/projects'
		});
	});

	it('tells a reader with no project of their own to create one first, rather than dropping the answer', () => {
		expect(
			startDestination(q('s=spa'), [p('p1', { editable: false })])
		).toEqual({ kind: 'noProject', href: '/admin/projects' });
		expect(startDestination(q('s=spa'), [])).toEqual({
			kind: 'noProject',
			href: '/admin/projects'
		});
	});

	it('never offers the administrators project', () => {
		expect(
			startDestination(q('s=spa'), [p('admin', { system: true }), p('p1')])
		).toEqual({ kind: 'go', href: '/admin/projects/p1/guide?s=spa' });
		expect(
			startDestination(q('s=spa'), [p('admin', { system: true })])
		).toEqual({ kind: 'noProject', href: '/admin/projects' });
	});

	it('encodes a project id in the address', () => {
		expect(startDestination(q('s=spa'), [p('a/b')])).toEqual({
			kind: 'go',
			href: '/admin/projects/a%2Fb/guide?s=spa'
		});
	});
});
