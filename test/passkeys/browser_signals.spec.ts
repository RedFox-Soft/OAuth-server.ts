import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { elysia } from 'lib/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present, shaped } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	SUB,
	holdingPasskey,
	mailOn,
	postPasskey,
	project,
	propsIn,
	securityPage,
	seedPasskey,
	signInPage,
	signedIn,
	type Project
} from './helpers.ts';

let acme: Project;
let sub: Project;

/* A device holding a passkey for `rpId` that no project here has a record of; answers its credential id. */
async function stranger(
	rpId: string,
	origin: string
): Promise<{ device: SoftAuthenticator; credentialId: string }> {
	const device = new SoftAuthenticator();
	const made = await device.create(
		{ challenge: 'AAAA', rp: { id: rpId }, user: { id: 'c29tZW9uZQ' } },
		{ origin }
	);
	return { device, credentialId: made.id };
}

const RefusedProps = Type.Object({
	errorMessage: Type.Optional(Type.String()),
	unknownPasskey: Type.Optional(
		Type.Object({ rpId: Type.String(), credentialId: Type.String() })
	)
});

/* The sign-in page the passkey door answers `device`'s passkey with, as its props carry it. */
async function refusedAt(at: Project, device: SoftAuthenticator) {
	const browser = new Browser(at.origin);
	const page = await signInPage(browser, at);
	const answer = await postPasskey(browser, device, at, page);
	expect(answer.status).toBe(400);
	return shaped(RefusedProps, propsIn(await answer.text()));
}

/* The signal attributes of the person's page, unescaped, or undefined where it carries none. */
function signalsIn(html: string) {
	const tag = /<div hidden data-passkey-signals([^>]*)>/.exec(html)?.[1];
	if (tag === undefined) return undefined;
	const attribute = (name: string) =>
		present(new RegExp(`${name}="([^"]*)"`).exec(tag)?.[1], name)
			.replace(/&quot;/g, '"')
			.replace(/&amp;/g, '&');
	return {
		rpId: attribute('data-rp-id'),
		userId: attribute('data-user-id'),
		accepted: shaped(
			Type.Array(Type.String()),
			JSON.parse(attribute('data-accepted'))
		),
		name: attribute('data-name'),
		displayName: attribute('data-display-name')
	};
}

async function endpointsAt(
	host: string,
	path = '/.well-known/passkey-endpoints'
) {
	return elysia.handle(new Request(`http://${host}${path}`));
}

/**
 * @proves The browser is told only what keeps a person's password manager right and touches nothing else: their page
 * lists exactly their passkeys this project accepts at this site and their current label, for their identity here
 * alone; a refused passkey is reported unknown only at a project's own site and only when no project on the instance
 * holds it, never at the instance's shared host; and every host answers where its passkeys are managed without ever
 * naming a project that is not its own.
 */
describe('what the browser is told about passkeys', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		sub = await project(SUB, { subdomain: true });
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	describe('from the person’s page', () => {
		it('lists exactly the passkeys this project accepts at this site, conditional ones included', async () => {
			const { email, accountId } = await holdingPasskey(acme);
			const [added] = await getPasskeyStore().listOf(acme.bucketId, accountId);
			const conditional = await seedPasskey(acme.bucketId, accountId, {
				conditional: true,
				createdVia: 'password'
			});
			await seedPasskey(acme.bucketId, accountId, { copiedAt: new Date() });
			await seedPasskey(acme.bucketId, accountId, { rpId: 'old.example.test' });
			const { browser } = await signedIn(acme, 'password', {
				email,
				accountId
			});

			const signals = present(
				signalsIn(await (await browser.request(securityPage(acme))).text()),
				'the signals'
			);

			const user = present(
				await getUserStore(acme.bucketId).find(accountId),
				'the person'
			);
			expect({ ...signals, accepted: [...signals.accepted].sort() }).toEqual({
				rpId: 'e.ly',
				userId: present(user.webauthnUserId, 'a passkey identity'),
				accepted: [
					present(added, 'the added passkey').credentialId,
					conditional.credentialId
				].sort(),
				name: `${email} · Acme`,
				displayName: `${email} · Acme`
			});
		});

		it('tells nothing for a person who never made a passkey here', async () => {
			const { browser } = await signedIn(acme, 'password');

			const html = await (await browser.request(securityPage(acme))).text();

			expect(signalsIn(html)).toBeUndefined();
		});
	});

	describe('after a refused passkey', () => {
		it('reports a passkey no project holds as unknown at a project’s own subdomain', async () => {
			const { device, credentialId } = await stranger('sub.e.ly', sub.origin);

			const refused = await refusedAt(sub, device);

			expect(refused.unknownPasskey).toEqual({
				rpId: 'sub.e.ly',
				credentialId
			});
		});

		it('reports nothing for a passkey another project holds for the same site', async () => {
			const { device, credentialId } = await stranger('sub.e.ly', sub.origin);
			const { accountId } = await signedIn(acme, 'password');
			await seedPasskey(acme.bucketId, accountId, {
				rpId: 'sub.e.ly',
				credentialId
			});

			const refused = await refusedAt(sub, device);

			expect(refused.unknownPasskey).toBeUndefined();
		});

		it('reports nothing at the instance’s shared host, for a project at a path', async () => {
			const { device } = await stranger('e.ly', acme.origin);

			const refused = await refusedAt(acme, device);

			expect(refused.unknownPasskey).toBeUndefined();
		});

		it('says the same words whether or not the browser is told', async () => {
			const atSub = await refusedAt(
				sub,
				(await stranger('sub.e.ly', sub.origin)).device
			);
			const atAcme = await refusedAt(
				acme,
				(await stranger('e.ly', acme.origin)).device
			);

			expect(atSub.errorMessage?.replace('sub.e.ly', 'X')).toBe(
				atAcme.errorMessage?.replace('Acme', 'X')
			);
		});
	});

	describe('where passkeys are managed', () => {
		it('answers no address at the instance’s own host', async () => {
			const answer = await endpointsAt('e.ly');

			expect(answer.status).toBe(200);
			expect(answer.headers.get('content-type')).toContain('application/json');
			expect(answer.headers.get('cache-control')).toBe('no-store');
			expect(await answer.json()).toEqual({});
		});

		it('names its own Sign-in and security page at a project’s subdomain', async () => {
			const answer = await endpointsAt('sub.e.ly');

			expect(await answer.json()).toEqual({
				enroll: 'http://sub.e.ly/account/security',
				manage: 'http://sub.e.ly/account/security'
			});
		});

		it('names its own page at a host of its own', async () => {
			forgetBucketAddresses();
			const bucket = await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: 'login people',
				host: 'login.acme.test'
			});
			await getBucketStore().update(bucket._id, { passkeyLogin: true });

			const answer = await endpointsAt('login.acme.test');

			expect(answer.status).toBe(200);
			expect(await answer.json()).toEqual({
				enroll: 'http://login.acme.test/account/security',
				manage: 'http://login.acme.test/account/security'
			});
		});

		it('is not found at a subdomain whose project does not accept passkeys', async () => {
			await getBucketStore().update(sub.bucketId, { passkeyLogin: false });
			forgetBucketAddresses();

			const answer = await endpointsAt('sub.e.ly');

			await getBucketStore().update(sub.bucketId, { passkeyLogin: true });
			forgetBucketAddresses();
			expect(answer.status).toBe(404);
		});

		it('is not found at a host the instance does not serve', async () => {
			expect((await endpointsAt('nobody.example.test')).status).toBe(404);
		});

		it('is not served beneath a project’s path', async () => {
			const answer = await endpointsAt(
				'e.ly',
				'/acme/.well-known/passkey-endpoints'
			);

			expect(answer.status).not.toBe(200);
		});
	});
});
