import {
	describe,
	it,
	expect,
	beforeEach,
	afterEach,
	setSystemTime
} from 'bun:test';

import { McpConfirmationStore } from 'lib/adapters/memory/mcpConfirmationStore.ts';

/*
 * The confirmation store's contract — specs/024-admin-mcp-control-plane/data-model.md §2.
 *
 * Memory implementation only, for the reason every store spec here gives: lib/adapters/mongodb/db.ts
 * connects at module scope and throws without MONGODB_URI, which this suite deliberately lacks, and
 * the constitution forbids real database calls in the suite (Principle III). The MongoDB class is
 * verified by hand per the feature's quickstart.
 *
 * The load-bearing properties are single-use and expiry. Both are what stop a confirmation from being
 * replayed against state that has changed since the operator approved it — which is the whole reason
 * the gate is server-side rather than a prompt in the agent's own interface.
 */

const base = {
	tool: 'client_delete',
	targetKey: 'id=proj_acme/clientId=billing',
	argumentsHash: 'abc123',
	principalId: 'admin-1',
	viaClientId: 'admin-mcp',
	report: { effect: 'deletes the client' }
};

describe('McpConfirmationStore (memory)', () => {
	let store: McpConfirmationStore;

	beforeEach(() => {
		store = new McpConfirmationStore();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('stamps an id and an expiry, and returns the record it stored', async () => {
		const issued = await store.issue({ ...base, ttlSeconds: 300 });

		expect(issued._id).toBeString();
		expect(issued._id.length).toBeGreaterThanOrEqual(8);
		expect(issued.tool).toBe(base.tool);
		expect(issued.targetKey).toBe(base.targetKey);
		expect(issued.argumentsHash).toBe(base.argumentsHash);
		expect(issued.principalId).toBe(base.principalId);
		expect(issued.viaClientId).toBe(base.viaClientId);
		expect(issued.report).toEqual(base.report);
		expect(issued.expiresAt.getTime() - issued.createdAt.getTime()).toBe(
			300_000
		);
	});

	it('issues distinct ids for identical requests', async () => {
		const a = await store.issue({ ...base, ttlSeconds: 300 });
		const b = await store.issue({ ...base, ttlSeconds: 300 });
		expect(a._id).not.toBe(b._id);
	});

	it('redeems once and never again', async () => {
		const issued = await store.issue({ ...base, ttlSeconds: 300 });

		const first = await store.redeem(issued._id);
		expect(first?._id).toBe(issued._id);

		// The single-use property. Anything else and a confirmed operation could be replayed.
		const second = await store.redeem(issued._id);
		expect(second).toBeNull();
	});

	it('reports an unknown token as absent rather than throwing', async () => {
		expect(await store.redeem('never-issued')).toBeNull();
	});

	it('refuses an expired token, and does not distinguish it from an unknown one', async () => {
		const issued = await store.issue({ ...base, ttlSeconds: 60 });

		setSystemTime(new Date(issued.expiresAt.getTime() + 1));

		// Same answer as an unknown token: neither is redeemable, and telling them apart would only
		// help someone probing.
		expect(await store.redeem(issued._id)).toBeNull();
	});

	it('honours a token right up to its expiry', async () => {
		const issued = await store.issue({ ...base, ttlSeconds: 60 });

		setSystemTime(new Date(issued.expiresAt.getTime() - 1));

		expect((await store.redeem(issued._id))?._id).toBe(issued._id);
	});

	it('spends the token even when it will be refused for a binding mismatch', async () => {
		// redeem() deletes before the caller compares bindings, so a token presented for the wrong
		// operation is consumed. Deliberate: it stops a caller probing the bindings one at a time.
		const issued = await store.issue({ ...base, ttlSeconds: 300 });
		await store.redeem(issued._id);
		expect(await store.redeem(issued._id)).toBeNull();
	});

	it('counts only live confirmations', async () => {
		expect(await store.count()).toBe(0);

		const a = await store.issue({ ...base, ttlSeconds: 60 });
		await store.issue({ ...base, ttlSeconds: 600 });
		expect(await store.count()).toBe(2);

		await store.redeem(a._id);
		expect(await store.count()).toBe(1);

		// An expired-but-unreaped record is not live. The memory adapter has no TTL monitor, so the
		// count has to filter — which is what keeps it agreeing with MongoDB's after an expiry.
		setSystemTime(new Date(Date.now() + 601_000));
		expect(await store.count()).toBe(0);
	});
});
