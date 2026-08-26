import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { resetOriginSalt } from 'lib/error_store/redact.ts';

/*
 * The capture path, exercised through the real global error handler rather than by calling captureFault
 * directly — the handler is where the classification lives, and a unit test of the capture function
 * would pass while the handler declined to call it.
 *
 * Every case provokes its fault on a route this spec mounts. The store is a process-wide singleton, so
 * assertions are scoped by the route the fault arose on, never by "the only group present".
 */
const enabled = ApplicationConfig['errorStore.enabled'];

function appThrowing(route: string, thrown: () => never) {
	return new Elysia().onError(errorHandler).get(route, () => thrown());
}

async function faultsOn(route: string) {
	await flushForTest();
	const page = await errorStore.list({ route });
	return page.groups;
}

describe('error store capture', () => {
	beforeEach(() => {
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
		resetOriginSalt();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	it('records an unexpected internal fault with the context to place it', async () => {
		const app = appThrowing('/boom-basic', () => {
			throw new Error('kaboom');
		});

		const response = await app.handle(
			new Request('http://e.ly/boom-basic?client_id=abc')
		);
		expect(response.status).toBe(500);

		const [group] = await faultsOn('/boom-basic');
		expect(group).toBeDefined();
		expect(group.status).toBe(500);
		expect(group.errorCode).toBe('server_error');
		expect(group.method).toBe('GET');
		expect(group.surface).toBe('oauth');
		expect(group.message).toContain('kaboom');
		// The location, parsed from the stack — never the stack itself.
		expect(group.origin.file).toContain('capture.spec');
		expect(group.origin.line).toBeGreaterThan(0);
		expect(group.occurrences).toBe(1);
	});

	it('groups a repeated fault and keeps the count exact', async () => {
		const app = appThrowing('/boom-repeat', () => {
			throw new Error('again');
		});

		for (let i = 0; i < 4; i += 1) {
			await app.handle(new Request('http://e.ly/boom-repeat'));
		}

		const groups = await faultsOn('/boom-repeat');
		expect(groups).toHaveLength(1);
		expect(groups[0].occurrences).toBe(4);
	});

	/*
	 * The response is what a caller already receives, plus one opaque member. Pinned because the whole
	 * feature is only safe if it changes nothing about how the server answers — the store is a side
	 * effect, not a new behaviour of the protocol.
	 */
	it('adds only a reference to the response, and no internal detail', async () => {
		const app = appThrowing('/boom-body', () => {
			throw new Error('secret-ish internal detail');
		});

		const response = await app.handle(new Request('http://e.ly/boom-body'));
		const body = (await response.json()) as Record<string, string>;

		expect(body.error).toBe('server_error');
		expect(body.error_description).toBe('An unexpected error occurred');
		expect(body.error_reference).toMatch(/^err_[A-Za-z0-9_-]{16}$/);
		// The fault's own message and its stack stay out of the response.
		expect(JSON.stringify(body)).not.toContain('secret-ish');
		expect(JSON.stringify(body)).not.toContain('at ');
	});

	it('resolves the reference it returned to the record it made', async () => {
		const app = appThrowing('/boom-ref', () => {
			throw new Error('findable');
		});

		const response = await app.handle(new Request('http://e.ly/boom-ref'));
		const { error_reference: reference } = (await response.json()) as {
			error_reference: string;
		};
		await flushForTest();

		const hit = await errorStore.findByReference(reference);
		expect(hit?.group.route).toBe('/boom-ref');
		expect(hit?.sample.reference).toBe(reference);
	});

	it('records the names of submitted fields, never their values', async () => {
		const app = appThrowing('/boom-fields', () => {
			throw new Error('fields');
		});

		await app.handle(
			new Request('http://e.ly/boom-fields?client_id=abc&scope=openid')
		);

		const [group] = await faultsOn('/boom-fields');
		expect(group.samples[0].submittedFields).toEqual(['client_id', 'scope']);
		expect(JSON.stringify(group)).not.toContain('abc');
		expect(JSON.stringify(group)).not.toContain('openid');
	});

	/*
	 * A deliberate rejection is correct behaviour, not a defect. If these were recorded the store would
	 * fill with traffic and the defects would be the minority — which is the failure mode that makes an
	 * error store useless rather than merely noisy.
	 */
	it('records nothing for a routine client rejection', async () => {
		const app = new Elysia().onError(errorHandler).get('/not-a-fault', () => {
			throw new Error('unused');
		});
		// A 404 for an unrouted path: answered, not a fault.
		const response = await app.handle(new Request('http://e.ly/no-such-path'));
		expect(response.status).toBe(404);

		await flushForTest();
		const page = await errorStore.list({ route: '/no-such-path' });
		expect(page.total).toBe(0);
	});

	it('writes nothing and adds no reference while the capability is off', async () => {
		ApplicationConfig['errorStore.enabled'] = false;
		const app = appThrowing('/boom-off', () => {
			throw new Error('unrecorded');
		});

		const response = await app.handle(new Request('http://e.ly/boom-off'));
		const body = (await response.json()) as Record<string, string>;

		expect(response.status).toBe(500);
		expect(body.error).toBe('server_error');
		expect(body.error_reference).toBeUndefined();
		expect(await faultsOn('/boom-off')).toHaveLength(0);
	});

	/*
	 * The store failing must not become a second failure the caller sees. This is the one property that,
	 * if it broke, would make the feature worse than not having it.
	 */
	it('answers normally when the store cannot accept a write', async () => {
		const original = errorStore.record;
		(errorStore as { record: unknown }).record = async () => {
			throw new Error('store unavailable');
		};

		try {
			const app = appThrowing('/boom-store-down', () => {
				throw new Error('fault while store is down');
			});
			const response = await app.handle(
				new Request('http://e.ly/boom-store-down')
			);
			const body = (await response.json()) as Record<string, string>;

			expect(response.status).toBe(500);
			expect(body.error).toBe('server_error');
			await flushForTest();
		} finally {
			(errorStore as { record: unknown }).record = original;
		}
	});

	it('renders the reference on an HTML error page', async () => {
		const app = appThrowing('/boom-html', () => {
			throw new Error('html fault');
		});

		const response = await app.handle(
			new Request('http://e.ly/boom-html', {
				headers: { accept: 'text/html' }
			})
		);
		const html = await response.text();

		expect(response.status).toBe(500);
		expect(html).toContain('reference: err_');
		expect(html).not.toContain('html fault');
	});
});
