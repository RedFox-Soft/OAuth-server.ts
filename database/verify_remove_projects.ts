/*
 * The migration that makes the bucket the only container (specs/099), against a real datastore: what each
 * project held moves to its clients and declarations, a second application changes nothing, and a client
 * listed by projects on different buckets stops the migration before it writes anything. Shared by
 * verify_mongodb.ts and verify_postgres.ts, which supply the raw reads and writes of their backend.
 */

type Doc = Record<string, unknown>;

export interface ProjectRemovalHooks {
	insertProject(doc: Doc): Promise<void>;
	insertClient(id: string, payload: Doc): Promise<void>;
	readClient(id: string): Promise<Doc | null>;
	insertResource(doc: Doc): Promise<void>;
	readResource(id: string): Promise<Doc | null>;
	/* One application of the migration's half for this backend; answers its report lines. */
	apply(): Promise<unknown>;
}

type Check = (name: string, ok: boolean, detail?: string) => void;

export async function verifyProjectRemoval(
	hooks: ProjectRemovalHooks,
	stamp: string,
	check: Check
): Promise<void> {
	const tenantBucket = `fidelity-tenant-${stamp}`;
	const ids = {
		first: `fidelity-first-${stamp}`,
		later: `fidelity-later-${stamp}`,
		onDefault: `fidelity-default-${stamp}`,
		app: `fidelity-app-${stamp}`,
		shared: `fidelity-shared-${stamp}`,
		ghost: `fidelity-ghost-${stamp}`,
		dynamic: `fidelity-dynamic-${stamp}`,
		tenantOnDefault: `fidelity-tenant-app-${stamp}`,
		resource: `${tenantBucket} https://api.invalid/${stamp}`,
		orphan: `@root https://orphan.invalid/${stamp}`
	};

	await hooks.insertProject({
		_id: ids.first,
		bucketId: tenantBucket,
		ownerGroupId: 'tenant-group',
		clientIds: [ids.app, ids.shared, ids.ghost],
		corsOrigins: ['https://first.example'],
		createdAt: new Date(1000)
	});
	await hooks.insertProject({
		_id: ids.later,
		bucketId: tenantBucket,
		ownerGroupId: 'tenant-group',
		clientIds: [ids.shared],
		corsOrigins: ['https://later.example'],
		createdAt: new Date(2000)
	});
	await hooks.insertProject({
		_id: ids.onDefault,
		bucketId: 'redfox',
		ownerGroupId: 'tenant-group',
		clientIds: [ids.tenantOnDefault],
		corsOrigins: [],
		createdAt: new Date(3000)
	});
	await hooks.insertClient(ids.app, {
		clientId: ids.app,
		'consent.require': true
	});
	await hooks.insertClient(ids.shared, { clientId: ids.shared });
	await hooks.insertClient(ids.dynamic, {
		clientId: ids.dynamic,
		registeredDynamically: true,
		registeredAtBucket: tenantBucket
	});
	await hooks.insertClient(ids.tenantOnDefault, {
		clientId: ids.tenantOnDefault,
		'consent.require': false
	});
	const declaration = {
		tokenFormat: 'jwt',
		accessTokenTTL: 900,
		trailingSlashSignificant: false,
		scopes: ['read'],
		createdAt: new Date(),
		updatedAt: new Date()
	};
	await hooks.insertResource({
		...declaration,
		_id: ids.resource,
		namespace: tenantBucket,
		identifier: `https://api.invalid/${stamp}`,
		name: 'api',
		projectId: ids.first
	});
	await hooks.insertResource({
		...declaration,
		_id: ids.orphan,
		namespace: '@root',
		identifier: `https://orphan.invalid/${stamp}`,
		name: 'orphan',
		projectId: `fidelity-gone-${stamp}`
	});

	const firstRun = await hooks.apply();
	const secondRun = await hooks.apply();

	const app = await hooks.readClient(ids.app);
	const shared = await hooks.readClient(ids.shared);
	const dynamic = await hooks.readClient(ids.dynamic);
	const tenantOnDefault = await hooks.readClient(ids.tenantOnDefault);
	const resource = await hooks.readResource(ids.resource);
	const orphan = await hooks.readResource(ids.orphan);

	check(
		"the project migration gives each listed client its project's bucket and origins",
		app?.bucketId === tenantBucket &&
			JSON.stringify(app.corsOrigins) ===
				JSON.stringify(['https://first.example']),
		JSON.stringify(app)
	);
	check(
		'a client listed by two projects of one bucket takes the earliest project’s origins, never the union',
		shared?.bucketId === tenantBucket &&
			JSON.stringify(shared.corsOrigins) ===
				JSON.stringify(['https://first.example']),
		JSON.stringify(shared)
	);
	check(
		'a self-registered client’s registeredAtBucket becomes its bucketId',
		dynamic?.bucketId === tenantBucket && !('registeredAtBucket' in dynamic),
		JSON.stringify(dynamic)
	);
	check(
		'a tenant’s client on the Default bucket loses its consent waiver',
		tenantOnDefault?.bucketId === 'redfox' &&
			tenantOnDefault['consent.require'] === true,
		JSON.stringify(tenantOnDefault)
	);
	check(
		'declarations take their project’s bucket, or their namespace’s or the Default bucket when the project is gone',
		resource?.bucketId === tenantBucket &&
			!('projectId' in resource) &&
			orphan?.bucketId === 'redfox' &&
			!('projectId' in orphan),
		`${JSON.stringify(resource)}; ${JSON.stringify(orphan)}`
	);
	const lines = (report: unknown) =>
		Array.isArray(report) ? report.map(String) : [];
	check(
		'the project migration reports the ghost and the orphan, and changes nothing the second time',
		lines(firstRun).includes(
			'client ids listed by a project with no stored client: 1'
		) &&
			lines(firstRun).includes('declarations whose project was missing: 1') &&
			lines(secondRun).includes('clients given their bucket: 0') &&
			lines(secondRun).includes('declarations given their bucket: 0') &&
			lines(secondRun).includes(
				'clients whose consent waiver was turned off: 0'
			),
		`${JSON.stringify(firstRun)}; second ${JSON.stringify(secondRun)}`
	);

	/* A client two buckets claim has no honest bucket: the migration refuses before it writes. */
	const contested = `fidelity-contested-${stamp}`;
	await hooks.insertClient(contested, { clientId: contested });
	await hooks.insertProject({
		_id: `fidelity-claim-a-${stamp}`,
		bucketId: `fidelity-a-${stamp}`,
		ownerGroupId: 'g',
		clientIds: [contested],
		corsOrigins: []
	});
	await hooks.insertProject({
		_id: `fidelity-claim-b-${stamp}`,
		bucketId: `fidelity-b-${stamp}`,
		ownerGroupId: 'g',
		clientIds: [contested],
		corsOrigins: []
	});
	let refusal = '';
	try {
		await hooks.apply();
	} catch (error) {
		refusal = error instanceof Error ? error.message : String(error);
	}
	const untouched = await hooks.readClient(contested);
	check(
		'a client listed by projects on different buckets stops the migration with nothing written',
		refusal.includes(contested) &&
			untouched !== null &&
			!('bucketId' in untouched),
		refusal
	);
}
