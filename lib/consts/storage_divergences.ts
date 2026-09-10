/*
 * Where the two production backends deliberately differ.
 *
 * Constitution Principle III's third binding condition: every behavioural divergence between two
 * adapters is either converged or declared with a written reason, never tolerated silently. This is
 * the declaration, and `database/verify_postgres.ts` fails on any difference it observes that is not
 * listed here — which is what makes the register a gate rather than a document.
 *
 * Import-free, like the storage inventory beside it, so the verification can read it without pulling
 * in a datastore.
 *
 * Two rules for adding an entry. `reason` says why converging is worse than differing, not merely
 * that they differ. `observable` says what a caller could actually notice — an entry whose answer is
 * "nothing" is a difference in implementation, not in behaviour, and does not belong here.
 */

export interface StorageDivergence {
	readonly id: string;
	readonly subject: string;
	readonly mongodb: string;
	readonly postgres: string;
	readonly reason: string;
	readonly observable: string;
}

export const STORAGE_DIVERGENCES: readonly StorageDivergence[] = [
	{
		id: 'expiry-reclamation-cadence',
		subject: 'when an expired record stops occupying storage',
		mongodb: "the server's TTL monitor, roughly once a minute",
		postgres: 'a sweeper this server runs, on the same interval',
		reason:
			'PostgreSQL has no TTL index, so the work has to happen somewhere. Both are housekeeping ' +
			'rather than correctness — expiry is enforced in the model layer on both backends — so the ' +
			'two cadences are allowed to differ as long as neither is unbounded.',
		observable:
			'the moment storage shrinks after a record expires, and nothing else: a read of an ' +
			'expired record is refused by the model on both backends before either sweep runs.'
	},
	{
		id: 'stale-expiry-on-untimed-upsert',
		subject: 'what an upsert with no ttl does to a stored expiry',
		mongodb: 'leaves the stored value in place',
		postgres: 'clears it, which is the natural ON CONFLICT write',
		reason:
			'Converging would mean either changing MongoDB behaviour inside a feature that promises not ' +
			'to, or writing PostgreSQL a deliberately unnatural statement to preserve a value nobody ' +
			'asked to keep. Neither buys anything while the difference is unreachable.',
		observable:
			'nothing, and a guard keeps it that way: a reaped area receives a ttl on every upsert and ' +
			'`Client`, the one area upserted without one, has no expiry index for a stale value to feed ' +
			'(test/storage_contract/ttl_pairing.spec.ts).'
	},
	{
		id: 'migration-record-atomicity',
		subject: "whether a migration's effect and its record are one write",
		mongodb: 'two writes: the record follows the effect',
		postgres: 'one transaction',
		reason:
			'A standalone `mongod` is a supported topology and has no multi-document transaction, so ' +
			'requiring one would drop support for it. The window this leaves is closed by requiring ' +
			'every migration step to be safe to apply twice, which is declared per migration.',
		observable:
			'after a crash between the two writes, MongoDB re-applies that migration on the next run. ' +
			'Safe by construction, and the reason `rerunnable` is a required field rather than a boolean.'
	},
	{
		id: 'unprovisioned-area-on-first-write',
		subject:
			'what a write to an area the database was never provisioned with does',
		mongodb:
			'creates the collection implicitly, without any of its declared indexes',
		postgres: 'fails: the relation does not exist',
		reason:
			'Converging would mean one of two bad trades. Teaching PostgreSQL to create the table on ' +
			'first write would adopt the trap rather than remove it — an area quietly created without ' +
			'its TTL or unique index is how documents that were meant to expire simply do not, and how ' +
			'a duplicate-registration race becomes reachable. Failing MongoDB on a missing collection ' +
			'would change the backend this feature promises not to touch. Both backends provision the ' +
			'same declared set from the same inventory, so the difference is only reachable by skipping ' +
			'that step.',
		observable:
			'a deployment that never ran its provisioning step: MongoDB serves and is subtly wrong, ' +
			'PostgreSQL refuses the operation outright. Provisioning is documented as required on both, ' +
			'and both scripts are idempotent so re-running is the fix.'
	},
	{
		id: 'startup-against-an-unreachable-datastore',
		subject: 'whether the server starts when its database cannot be reached',
		mongodb: 'no: the driver connects at module scope and boot throws',
		postgres:
			'no: the handle connects lazily, so a startup probe is what refuses',
		reason:
			'Converged deliberately, and listed because the convergence is load-bearing rather than ' +
			'incidental. The lazy handle is what keeps every module under lib/adapters/postgres/ ' +
			'importable with no connection and no POSTGRES_URL, which the MongoDB adapter is not; the ' +
			'same laziness would let this server come up against a dead database and start answering. ' +
			'The startup probe closes that, so removing it re-opens a divergence rather than merely ' +
			'dropping a check.',
		observable:
			'nothing, while the probe stands: both backends exit at boot rather than serve. With it ' +
			'removed, a PostgreSQL deployment would accept traffic it cannot serve — which is why ' +
			'`database/verify_postgres.ts` boots the app against a dead port and asserts it dies.'
	},
	{
		id: 'email-case-normalisation',
		subject: 'where an end-user address is lower-cased',
		mongodb: 'in the store, on write and on read',
		postgres: 'in the store, on write and on read',
		reason:
			'Converged deliberately, and listed so the convergence is visible: the unique index is on ' +
			'the stored value on both backends rather than on a `lower()` expression, which keeps the ' +
			'normalisation in one place instead of in two datastores’ index definitions.',
		observable:
			'nothing. The in-memory store keeps the address as supplied, which is a separate and ' +
			'previously recorded difference, not this one.'
	}
];
