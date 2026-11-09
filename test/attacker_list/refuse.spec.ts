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
import { ApplicationConfig, settingsApplied } from 'lib/configs/application.js';
import { hourOf, takeHour } from 'lib/attack_reports/tally.ts';
import { now } from 'lib/telemetry/clock.ts';
import {
	clockAt,
	iso,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer,
	type ListLine,
	type Signer
} from './helper.ts';
import {
	attempt,
	INVALID,
	PASSWORD,
	person,
	REFUSAL_TITLE,
	seedProject,
	setGuessing,
	WRONG,
	withoutUid
} from './door.ts';

let bucketId: string;
let foxtrust: Signer;
let undoClock: () => void = () => {};

/* Lists `lines` and makes it the list in effect, at 0.1 h into the case. */
async function listing(...lines: ListLine[]): Promise<void> {
	const published = publication();
	await published.publish({
		version: `a${String(seconds(0))}`,
		builtAt: iso(0),
		validUntil: iso(3),
		lines,
		by: foxtrust
	});
	expect(await pass(foxtrust)).toBe('accepted');
}

function at(hours: number): void {
	undoClock();
	undoClock = clockAt(hours);
}

async function failThrice(email: string, from: string): Promise<void> {
	for (let i = 0; i < 3; i += 1) {
		const answer = await attempt(email, WRONG, from);
		expect(answer.text).toContain(INVALID);
	}
}

/**
 * @proves A project that refuses password sign-ins from listed addresses refuses one only after it has just failed
 * passwords here (at once when FoxTrust corroborates it), never on an old listing, never for a proxy, edge or
 * unattributed caller, without checking a password, identically for any email, in the person's language, and
 * without reporting the refusal as an attack; a person who types the right password first still signs in.
 */
describe('a project refusing password sign-ins from listed addresses', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		bucketId = await seedProject();
		await setGuessing(bucketId, { mode: 'refuse', exempt: [] });
	});

	beforeEach(async () => {
		resetAttackerList();
		foxtrust = await signer();
		undoClock = clockAt(0.1);
	});

	afterEach(() => {
		undoClock();
	});

	it('refuses the fourth attempt after three failures without checking a password', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1) });
		await failThrice(email, from);

		const verify = spyOn(Bun.password, 'verify');
		try {
			const answer = await attempt(email, PASSWORD, from);
			expect({
				refused: answer.text.includes(REFUSAL_TITLE),
				line: answer.text.includes(`listed-address · ${from} · `),
				verified: verify.mock.calls.length
			}).toEqual({ refused: true, line: true, verified: 0 });
		} finally {
			verify.mockRestore();
		}
	});

	it('signs in a person on a listed address who types the right password first', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1) });

		const answer = await attempt(email, PASSWORD, from);

		expect(answer.status).toBe(303);
	});

	it('refuses an address FoxTrust corroborates at the first attempt', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1), corroborated: true });

		const answer = await attempt(email, PASSWORD, from);

		expect(answer.text).toContain(REFUSAL_TITLE);
	});

	it('never refuses an address last seen more than 48 hours ago', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({
			network: from,
			lastSeen: seconds(-49),
			corroborated: true
		});
		await failThrice(email, from);

		const answer = await attempt(email, WRONG, from);

		expect(answer.text).toContain(INVALID);
	});

	it('keeps refusing a listed address that keeps trying', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1) });
		await failThrice(email, from);

		const refused: boolean[] = [];
		for (const hours of [0.5, 1, 1.5, 2]) {
			at(hours);
			refused.push(
				(await attempt(email, PASSWORD, from)).text.includes(REFUSAL_TITLE)
			);
		}

		expect(refused).toEqual([true, true, true, true]);
	});

	it('gives an address quiet for an hour three attempts again', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1) });
		await failThrice(email, from);
		at(1.2);

		const answer = await attempt(email, WRONG, from);

		expect(answer.text).toContain(INVALID);
	});

	it('never consults the list for a caller whose address is a trusted proxy', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1), corroborated: true });
		ApplicationConfig['clientAddress.source'] = 'listed';
		ApplicationConfig['clientAddress.trustedProxies'] = [from];
		settingsApplied(['clientAddress.trustedProxies']);
		try {
			const answer = await attempt(email, PASSWORD, from);
			expect(answer.status).toBe(303);
		} finally {
			ApplicationConfig['clientAddress.source'] = 'automatic';
			ApplicationConfig['clientAddress.trustedProxies'] = [];
			settingsApplied(['clientAddress.trustedProxies']);
		}
	});

	it('never consults the list for a Cloudflare edge address', async () => {
		const email = await person(bucketId);
		await listing({
			network: '104.16.0.9',
			lastSeen: seconds(-1),
			corroborated: true
		});

		const answer = await attempt(email, PASSWORD, '104.16.0.9');

		expect(answer.status).toBe(303);
	});

	it('never consults the list for a request with no address', async () => {
		const email = await person(bucketId);
		await listing({
			network: listedAddress(),
			lastSeen: seconds(-1),
			corroborated: true
		});

		const answer = await attempt(email, PASSWORD);

		expect(answer.status).toBe(303);
	});

	it('answers the same refusal whatever email is typed', async () => {
		const from = listedAddress();
		const known = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1), corroborated: true });

		const forKnown = await attempt(known, WRONG, from);
		const forUnknown = await attempt('nobody-here@x.io', WRONG, from);

		expect({ status: forUnknown.status, page: withoutUid(forUnknown) }).toEqual(
			{
				status: 400,
				page: withoutUid(forKnown)
			}
		);
	});

	it('leaves list refusals out of the attack report', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1), corroborated: true });
		takeHour(hourOf(now()));
		for (let i = 0; i < 12; i += 1) await attempt(email, WRONG, from);

		const counted = takeHour(hourOf(now()))?.addresses.get(from)?.counts;

		expect(counted?.signin_failures).toBeUndefined();
	});

	it('refuses in Russian for a person reading Russian', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1), corroborated: true });

		const answer = await attempt(email, WRONG, from, 'ru');

		expect(answer.text).toContain(
			'Вход по паролю из этой сети сейчас недоступен'
		);
	});

	it('refuses in Chinese for a person reading Chinese', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1), corroborated: true });

		const answer = await attempt(email, WRONG, from, 'zh-CN');

		expect(answer.text).toContain('此网络暂时无法使用密码登录');
	});
});
