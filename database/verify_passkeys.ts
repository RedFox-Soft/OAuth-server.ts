/*
 * People's passkeys (specs/139) against a real datastore: what the in-memory store cannot show.
 *
 *   MONGODB_URI=… DATABASE_NAME=oauth_scratch          bun database/verify_passkeys.ts
 *   POSTGRES_URL=postgres://…/oauth_scratch            bun database/verify_passkeys.ts
 *
 * Run once per backend, after `db:setup` / `db:setup:pg` has provisioned the inventory; it uses whichever one
 * connection string names, and refuses both. It writes and then removes its own records, and refuses a database
 * whose name does not say it is disposable, as the other verify scripts do.
 *
 * A script rather than a spec (Constitution Principle III): the in-memory store checks with no `await` inside a
 * write, so `bun test` cannot prove that the unique `{bucketId, credentialId}` index exists and refuses a second add,
 * that the conditional counter write lets exactly one of two racing sign-ins through, that the removals by person,
 * by project and "added since" remove exactly theirs, or that one "This wasn't me" link is spent once.
 */

const THROWAWAY =
	/(^|[-_])(test|tmp|scratch|throwaway|migrationcheck)([-_]|$)/i;

const mongo = process.env.MONGODB_URI;
const postgres = process.env.POSTGRES_URL;
if (Boolean(mongo) === Boolean(postgres)) {
	console.error('set exactly one of MONGODB_URI and POSTGRES_URL');
	process.exit(1);
}
const database = mongo
	? (process.env.DATABASE_NAME ?? '')
	: new URL(postgres ?? '').pathname.replace(/^\//, '');
if (!THROWAWAY.test(database)) {
	console.error(
		`refusing to run against '${database}': the database name must contain test, tmp, scratch, ` +
			'throwaway or migrationcheck as a whole word.'
	);
	process.exit(1);
}

/* After the guard, for the reason verify_postgres.ts gives: importing the adapters connects. */
const { getPasskeyStore } = await import('../lib/adapters/index.js');
type Passkey = import('../lib/adapters/types.js').Passkey;

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
	console.log(
		`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`
	);
	if (!ok) failures += 1;
}

const store = getPasskeyStore();
const stamp = Date.now();
const bucketId = `verify-passkeys-${String(stamp)}`;
const other = `verify-passkeys-other-${String(stamp)}`;
const base = new Date();
const at = (seconds: number) => new Date(base.getTime() + seconds * 1000);

function id(): string {
	return Buffer.from(crypto.getRandomValues(new Uint8Array(16)))
		.toString('base64url')
		.slice(0, 22);
}

function passkey(fields: Partial<Passkey> = {}): Passkey {
	return {
		_id: id(),
		bucketId,
		accountId: 'anna',
		credentialId: id(),
		publicKey: 'pQECAyYgASFYIA',
		rpId: 'auth.example.test',
		counter: 0,
		backupEligible: true,
		backedUp: true,
		transports: ['internal', 'hybrid'],
		aaguid: '00000000-0000-0000-0000-000000000000',
		createdAt: at(0),
		createdVia: 'password_code',
		createdOn: { browser: 'chrome', system: 'windows' },
		...fields
	};
}

/* ---------------------------------------------------------- one credential id per project */

const first = passkey();
check('a passkey is stored', (await store.create(first)) === 'created');
check(
	'a second passkey with the same credential id in the project is refused',
	(await store.create(passkey({ credentialId: first.credentialId }))) ===
		'exists'
);
check(
	'the same credential id in another project is its own passkey',
	(await store.create(
		passkey({ bucketId: other, credentialId: first.credentialId })
	)) === 'created'
);
const found = await store.findByCredential(bucketId, first.credentialId);
check(
	'the sign-in lookup finds the passkey and reads it back whole',
	found?._id === first._id &&
		found.createdAt.getTime() === first.createdAt.getTime() &&
		found.transports.length === 2
);

/* ---------------------------------------------------------- the conditional counter write */

const counting = passkey({ counter: 5 });
await store.create(counting);
const raced = await Promise.all(
	Array.from({ length: 8 }, () =>
		store.recordUse(bucketId, counting._id, {
			counter: 6,
			backedUp: true,
			at: at(10)
		})
	)
);
check(
	'of eight racing sign-ins with one counter, exactly one is recorded',
	raced.filter(Boolean).length === 1,
	JSON.stringify(raced)
);
check(
	'a counter that does not move forward is not recorded',
	!(await store.recordUse(bucketId, counting._id, {
		counter: 6,
		backedUp: true,
		at: at(20)
	}))
);
const zero = passkey();
await store.create(zero);
const zeros = [
	await store.recordUse(bucketId, zero._id, {
		counter: 0,
		backedUp: false,
		at: at(30)
	}),
	await store.recordUse(bucketId, zero._id, {
		counter: 0,
		backedUp: false,
		at: at(40)
	})
];
const afterZeros = await store.find(bucketId, zero._id);
check(
	'a counter that stays at zero is recorded at every use',
	zeros.every(Boolean) &&
		afterZeros?.lastUsedAt?.getTime() === at(40).getTime() &&
		!afterZeros.backedUp
);
await store.markCopied(bucketId, zero._id, at(50));
await store.markCopied(bucketId, zero._id, at(60));
const copied = await store.find(bucketId, zero._id);
check(
	'a copy mark keeps its first time',
	copied?.copiedAt?.getTime() === at(50).getTime()
);
check(
	'a passkey marked copied records no use',
	!(await store.recordUse(bucketId, zero._id, {
		counter: 0,
		backedUp: false,
		at: at(70)
	}))
);

/* ---------------------------------------------------------- "This wasn't me", once */

const disowned = passkey({
	notMe: { digest: 'd'.repeat(64), exp: Math.floor(Date.now() / 1000) + 600 }
});
await store.create(disowned);
const now = Math.floor(Date.now() / 1000);
const spent = await Promise.all(
	Array.from({ length: 4 }, () =>
		store.spendNotMe(bucketId, disowned._id, 'd'.repeat(64), now)
	)
);
check(
	'of four racing confirmations of one link, exactly one spends it',
	spent.filter(Boolean).length === 1,
	JSON.stringify(spent)
);
const late = passkey({ notMe: { digest: 'e'.repeat(64), exp: now - 1 } });
await store.create(late);
check(
	'a link past its end is not spent',
	!(await store.spendNotMe(bucketId, late._id, 'e'.repeat(64), now))
);

/* ---------------------------------------------------------- removals */

check(
	'renaming writes and clears a name',
	(await store.rename(bucketId, 'anna', first._id, 'Work laptop')) &&
		(await store.find(bucketId, first._id))?.name === 'Work laptop' &&
		(await store.rename(bucketId, 'anna', first._id, undefined)) &&
		(await store.find(bucketId, first._id))?.name === undefined
);
check(
	'another person cannot remove the passkey',
	!(await store.remove(bucketId, 'bob', first._id))
);

await store.create(passkey({ accountId: 'bob' }));
const early = passkey({ createdAt: at(-3600) });
const later = passkey({ createdAt: at(3600) });
await store.create(early);
await store.create(later);
const sinceRemoved = await store.removeAddedSince(bucketId, 'anna', at(0));
const left = await store.listOf(bucketId, 'anna');
check(
	'"added since" removes the person’s passkeys from that time on and keeps the earlier one',
	left.length === 1 && left[0]?._id === early._id && sinceRemoved > 0,
	`${String(sinceRemoved)} removed, ${String(left.length)} left`
);
{
	/*
	 * Holders at one RP ID (specs/140 research R6): Anna's two count once with 2, a copied passkey and one made for
	 * another RP ID count for nobody.
	 */
	const holding = `verify-passkeys-holding-${String(stamp)}`;
	await store.create(passkey({ bucketId: holding }));
	await store.create(passkey({ bucketId: holding }));
	await store.create(passkey({ bucketId: holding, accountId: 'bob' }));
	const copied = passkey({ bucketId: holding, accountId: 'carol' });
	await store.create(copied);
	await store.markCopied(holding, copied._id, at(10));
	await store.create(
		passkey({
			bucketId: holding,
			accountId: 'dave',
			rpId: 'other.example.test'
		})
	);
	const held = (await store.holdingIn(holding, 'auth.example.test'))
		.map((row) => `${row.accountId}:${String(row.passkeys)}`)
		.sort();
	check(
		'holders at one RP ID count each person once, without copied passkeys or another RP ID',
		JSON.stringify(held) === JSON.stringify(['anna:2', 'bob:1']),
		held.join(', ')
	);
	await store.removeAllIn(holding);
}
check(
	'removing a person’s passkeys leaves everyone else’s',
	(await store.removeAllOf(bucketId, 'anna')) === 1 &&
		(await store.countOf(bucketId, 'anna')) === 0 &&
		(await store.countOf(bucketId, 'bob')) === 1
);
check(
	'removing a project’s passkeys leaves another project’s',
	(await store.removeAllIn(bucketId)) === 1 &&
		(await store.countOf(other, 'anna')) === 1
);
await store.removeAllIn(other);

console.log(
	failures === 0 ? 'all checks passed' : `${String(failures)} FAILED`
);
process.exit(failures === 0 ? 0 : 1);
