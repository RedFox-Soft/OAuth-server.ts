import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import {
	clockAt,
	iso,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer
} from '../attacker_list/helper.ts';
import { REFUSAL_TITLE } from '../attacker_list/door.ts';
import {
	ACME,
	Browser,
	codeAfter,
	holdingPasskey,
	mailOn,
	passkeyOfferIn,
	postPasskey,
	project,
	signInPage,
	textOf,
	type Project
} from './helpers.ts';

let acme: Project;
let undoClock: () => void = () => {};

/* A corroborated listing of `address`, so a project that refuses listed addresses refuses it at once. */
async function listing(address: string): Promise<void> {
	const foxtrust = await signer();
	await publication().publish({
		version: `a${String(seconds(0))}`,
		builtAt: iso(0),
		validUntil: iso(3),
		lines: [{ network: address, lastSeen: seconds(-1), corroborated: true }],
		by: foxtrust
	});
	expect(await pass(foxtrust)).toBe('accepted');
}

/**
 * @proves FoxTrust's attacker list refuses passwords from a listed address and nothing else: the page that tells a
 * person so still offers their passkey, and the passkey signs them in from that address.
 */
describe('a passkey from an address the attacker list refuses passwords from', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'listed' });
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, {
			passwordGuessing: { mode: 'refuse', exempt: [] }
		});
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		resetAttackerList();
		undoClock = clockAt(0.1);
	});

	afterEach(() => {
		undoClock();
		setPeerResolverForTests(null);
	});

	it('is offered beside the refusal', async () => {
		const address = listedAddress();
		await listing(address);
		setPeerResolverForTests(() => address);

		const { html } = await signInPage(new Browser(acme.origin), acme);

		expect(textOf(html)).toContain(REFUSAL_TITLE);
		expect(passkeyOfferIn(html)).toMatchObject({ remember: false });
		expect(html).toMatch(/<input[^>]*autocomplete="username webauthn"/i);
		expect(html).not.toMatch(/name="password"/);
	});

	it('signs the person in from that address', async () => {
		const { device } = await holdingPasskey(acme);
		const address = listedAddress();
		await listing(address);
		setPeerResolverForTests(() => address);
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);

		const posted = await postPasskey(browser, device, acme, page);

		expect(await codeAfter(browser, posted, page.url)).toBeString();
	});
});
