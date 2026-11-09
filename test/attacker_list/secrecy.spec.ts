import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { eventBus } from 'lib/event_bus.ts';
import { adapter, adminAuditStore } from 'lib/adapters/index.ts';
import {
	clockAt,
	iso,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer
} from './helper.ts';
import {
	attempt,
	person,
	REFUSAL_TITLE,
	seedProject,
	setGuessing,
	WRONG
} from './door.ts';

let bucketId: string;
let undoClock: () => void = () => {};

/**
 * @proves A refused address reaches nothing the server keeps or emits — no event, log line, audit entry or counter —
 * and appears only on the refused person's own page.
 */
describe('a refused address and what the server keeps', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		bucketId = await seedProject();
		await setGuessing(bucketId, { mode: 'refuse', exempt: [] });
	});

	beforeEach(() => {
		resetAttackerList();
		undoClock = clockAt(0.1);
	});

	afterEach(() => {
		undoClock();
	});

	it('appears in no event, log line, audit entry or counter', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		const foxtrust = await signer();
		await publication().publish({
			version: `a${String(seconds(0))}`,
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: from, lastSeen: seconds(-1) }],
			by: foxtrust
		});
		await pass(foxtrust);
		const emitted = spyOn(eventBus, 'emit');
		const logged = [
			spyOn(console, 'log'),
			spyOn(console, 'info'),
			spyOn(console, 'warn'),
			spyOn(console, 'error')
		];

		const pages: string[] = [];
		try {
			for (let i = 0; i < 6; i += 1) {
				pages.push((await attempt(email, WRONG, from)).text);
			}
		} finally {
			emitted.mockRestore();
			for (const spy of logged) spy.mockRestore();
		}

		const kept = JSON.stringify({
			events: emitted.mock.calls,
			logs: logged.map((spy) => spy.mock.calls),
			audit: await adminAuditStore.list({ targetId: bucketId }),
			counters: await adapter('PasswordGuessingTally').findByIndexed(
				'bucketId',
				bucketId
			)
		});
		expect({
			refused: pages.some((page) => page.includes(REFUSAL_TITLE)),
			kept: kept.includes(from)
		}).toEqual({ refused: true, kept: false });
	});
});
