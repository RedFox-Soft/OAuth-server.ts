import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';

const HOST = 'http://acme.example.test';

async function get(path: string, cookie = ''): Promise<Response> {
	return elysia.handle(new Request(`${HOST}${path}`, { headers: { cookie } }));
}

function framingOf(res: Response) {
	return {
		frameAncestors: res.headers
			.get('content-security-policy')
			?.includes("frame-ancestors 'none'"),
		xFrameOptions: res.headers.get('x-frame-options')
	};
}

/**
 * @proves A bucket served at a hostname of its own refuses to have its sign-out confirmation and device-code
 * pages framed by another site, as every other bucket's are — those pages carry a button a framing site could
 * trick a person into pressing.
 */
describe('framing of a host-addressed bucket’s confirmation pages', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'csp' });
		forgetBucketAddresses();
		await getBucketStore().create({
			_id: 'acme-bucket',
			name: 'acme',
			host: 'acme.example.test',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
	});

	it('refuses framing of the sign-out confirmation', async () => {
		const cookie = await setup.login({ bucketId: 'acme-bucket' });

		const res = await get('/logout', cookie);

		expect(res.status).toBe(200);
		expect(framingOf(res)).toEqual({
			frameAncestors: true,
			xFrameOptions: 'DENY'
		});
		expect(await res.text()).toContain('action="/logout/confirm"');
	});

	it('refuses framing of the device-code page', async () => {
		const res = await get('/device');

		expect(res.status).toBe(200);
		expect(framingOf(res)).toEqual({
			frameAncestors: true,
			xFrameOptions: 'DENY'
		});
	});
});
