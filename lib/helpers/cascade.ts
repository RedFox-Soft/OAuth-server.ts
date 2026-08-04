import { adapter } from 'lib/adapters/index.js';
import { STORAGE_INVENTORY } from 'lib/consts/storage_inventory.js';

/*
 * The one deletion cascade. Every area it touches comes from the ownership declaration in
 * lib/consts/storage_inventory.ts — no area is named here, and no caller names one either.
 *
 * That indirection is the whole point. A cascade written out per entity works on the day it is written
 * and then fails silently: the first time a storage area is added, its records simply outlive the
 * principal they belong to and nothing says so. Two of the areas swept below are the proof — a
 * client-credentials token carries no grantId, so collecting grant ids and revoking by them never
 * reaches it, and a registration access token may carry no expiry, so what it leaves behind is not even
 * bounded by a TTL. Both are easy to forget and neither announces itself.
 *
 * Containers are not cascaded, deliberately: a project's clients and a bucket's users are things an
 * operator can see and name, so those deletions are refused with the contents listed instead. Nobody can
 * be asked to enumerate the tokens a client issued.
 */

export interface CascadeResult {
	/* Area name → records destroyed. Areas that swept nothing are present, with 0. */
	readonly destroyed: Readonly<Record<string, number>>;
	/* Non-empty only on partial failure. The principal is already gone by then. */
	readonly failedAreas: readonly string[];
}

/*
 * Swept before anything else on a client cascade. Every other swept area carries an `expiresAt`, so a
 * cascade that dies partway leaves residue bounded by each area's own TTL — except this one, whose
 * records may be issued with no expiry at all. Going first is what makes "the residue is bounded" true
 * rather than hopeful.
 */
const UNBOUNDED_AREA = 'RegistrationAccessToken';

interface AreaSweep {
	readonly area: string;
	readonly run: () => Promise<number>;
}

function ownerSweeps(owner: 'account' | 'client', value: string): AreaSweep[] {
	return STORAGE_INVENTORY.flatMap((area) => {
		const field = area.owners[owner];
		/*
		 * Model areas only, because a sweep resolves through `adapter()`. Nothing is skipped silently: the
		 * drift guard fails the suite if a store or per-bucket area ever declares an owner, so this filter
		 * can never quietly drop one.
		 */
		if (area.kind !== 'model' || field === null) return [];
		return [
			{
				area: area.name,
				run: () => adapter(area.name).destroyByOwner(field, value)
			}
		];
	});
}

async function runSweeps(sweeps: readonly AreaSweep[]): Promise<CascadeResult> {
	const destroyed: Record<string, number> = {};
	const failedAreas: string[] = [];

	/*
	 * Settled, not `all`: aborting on the first failure would leave *more* behind than continuing, and the
	 * caller needs to name every area that failed rather than only the first.
	 */
	const outcomes = await Promise.allSettled(sweeps.map((sweep) => sweep.run()));
	for (const [index, outcome] of outcomes.entries()) {
		const sweep = sweeps[index];
		if (!sweep) continue;
		if (outcome.status === 'fulfilled') {
			destroyed[sweep.area] = outcome.value;
		} else {
			failedAreas.push(sweep.area);
		}
	}

	return { destroyed, failedAreas };
}

function merge(...results: readonly CascadeResult[]): CascadeResult {
	return {
		destroyed: Object.assign({}, ...results.map((r) => r.destroyed)),
		failedAreas: results.flatMap((r) => [...r.failedAreas])
	};
}

/* Every record naming this client as its owner, across every area that declares a client owner. */
export async function cascadeForClient(
	clientId: string
): Promise<CascadeResult> {
	const sweeps = ownerSweeps('client', clientId);

	const unbounded = await runSweeps(
		sweeps.filter((sweep) => sweep.area === UNBOUNDED_AREA)
	);
	const bounded = await runSweeps(
		sweeps.filter((sweep) => sweep.area !== UNBOUNDED_AREA)
	);

	return merge(unbounded, bounded);
}

/*
 * Every record naming this account as its owner, plus the one record that is addressed rather than
 * scanned.
 *
 * `verificationResendId` is `${bucketId}:${email}` and must be computed by the caller *before* it
 * destroys the account row — nothing else records the email, so the obvious ordering (destroy, then
 * cascade) skips that record and raises no error anywhere. Taking the already-computed id, rather than
 * the bucket and the account, is what makes that ordering visible in the signature: this function cannot
 * be called correctly after the account is gone.
 */
export async function cascadeForAccount(
	accountId: string,
	verificationResendId: string | null
): Promise<CascadeResult> {
	const sweeps: AreaSweep[] = ownerSweeps('account', accountId);

	if (verificationResendId !== null) {
		sweeps.push({
			area: 'VerificationResend',
			run: async () => {
				const store = adapter('VerificationResend');
				/* Read first only so the count is honest; destroy is a no-op on a missing id either way. */
				const existing = await store.find(verificationResendId);
				if (!existing) return 0;
				await store.destroy(verificationResendId);
				return 1;
			}
		});
	}

	return runSweeps(sweeps);
}
