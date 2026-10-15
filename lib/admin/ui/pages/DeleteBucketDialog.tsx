import { useEffect, useRef, useState } from 'react';
import { ConfirmDestruction } from '../ConfirmDestruction.js';
import { useFeedback } from '../frame/feedback.js';
import { request } from '../frame/request.js';
import { useNavigate } from '../frame/router.js';
import { bucketHref } from '../frame/routes.js';
import type { BucketSummary } from './bucketView.js';

/*
 * Deleting a bucket, from the list's menu or the bucket's Danger zone — one dialog for both (specs/081).
 *
 * Two acts share it (specs/090). `schedule` is what Delete does now: the bucket stops answering at once and is
 * destroyed thirty days later unless someone restores it. `purge` is Delete now, on a bucket already scheduled:
 * the destruction itself, at once. Both destroy the same accounts in the end, so both ask the same consent.
 *
 * The account count is read when the dialog opens, never taken from a list: it is the number the operator
 * consents to destroy, and the server refuses the deletion if it changed (`expect`). When it did, the dialog
 * reads it again, unticks the consent by starting over, and says so — the operator agrees to the new number,
 * not the old one.
 */
export interface BucketDeleted {
	accounts: number;
	// Set when the bucket was scheduled rather than destroyed: the moment it will be.
	purgeAt?: string;
}

const HOLD_DAYS = 30;

export function DeleteBucketDialog({
	bucket,
	mode = 'schedule',
	onClose,
	onDeleted
}: {
	bucket: { _id: string; name: string };
	mode?: 'schedule' | 'purge';
	onClose: () => void;
	onDeleted: (result: BucketDeleted) => void;
}) {
	const feedback = useFeedback();
	const navigate = useNavigate();
	const [accounts, setAccounts] = useState<number | null>(null);
	const [changed, setChanged] = useState(false);
	// Bumped to start the dialog over, consent unticked, when the count moved under the operator.
	const [round, setRound] = useState(0);
	const [busy, setBusy] = useState(false);
	// When the dialog opened: the restore deadline it states is counted from here, not re-read on every render.
	const [openedAt] = useState(() => Date.now());
	const summaryPath = `/admin/api/projects/${encodeURIComponent(bucket._id)}/summary`;
	// The count is read once per opening, whatever the parent passes as `onClose` on each render.
	const close = useRef(onClose);
	useEffect(() => {
		close.current = onClose;
	}, [onClose]);

	useEffect(() => {
		let current = true;
		void request<BucketSummary>('GET', summaryPath).then((result) => {
			if (!current) return;
			if (result.ok) {
				setAccounts(result.data.users);
				return;
			}
			// A count it never learned would read as "empty", so the dialog does not open on a failed read.
			feedback.failed(result);
			close.current();
		});
		return () => {
			current = false;
		};
	}, [summaryPath, feedback]);

	async function onConfirm(withCascade: boolean) {
		if (accounts === null) return;
		setBusy(true);
		const params = new URLSearchParams();
		if (withCascade) {
			params.set('cascade', 'endusers');
			params.set('expect', String(accounts));
		}
		const qs = params.toString();
		const path = `/admin/api/projects/${encodeURIComponent(bucket._id)}${mode === 'purge' ? '/purge' : ''}`;
		const result = await request<{
			endUsersDestroyed?: number;
			scheduled?: { purgeAt: string };
		}>(mode === 'purge' ? 'POST' : 'DELETE', `${path}${qs ? `?${qs}` : ''}`);
		setBusy(false);
		if (result.ok) {
			onDeleted({
				accounts: result.data.endUsersDestroyed ?? accounts,
				purgeAt: result.data.scheduled?.purgeAt
			});
			return;
		}
		if (result.status === 409) {
			const fresh = await request<BucketSummary>('GET', summaryPath);
			if (fresh.ok && fresh.data.users !== accounts) {
				setAccounts(fresh.data.users);
				setChanged(true);
				setRound((n) => n + 1);
				return;
			}
		}
		feedback.failed(result);
	}

	if (accounts === null) return null;

	// Shown before the server answers, so it is the date as of opening; the server's own is what the banner reads after.
	const until = new Date(
		openedAt + HOLD_DAYS * 24 * 60 * 60 * 1000
	).toLocaleDateString();
	const consequences =
		mode === 'purge'
			? [
					'The project is gone permanently. There is nothing left to inspect or restore.',
					'Its sign-in address is freed, and another project may take it.'
				]
			: [
					'It stops answering at once: nobody can sign in and no app can get a token.',
					`You can restore it until ${until}. After that it is deleted permanently, with everything in it.`,
					'Access tokens it already issued may still be accepted by an app that checks them itself, until they expire.'
				];

	return (
		<ConfirmDestruction
			key={round}
			open
			title={
				mode === 'purge'
					? `Delete ${bucket.name} now?`
					: `Delete ${bucket.name}?`
			}
			okText={mode === 'purge' ? 'Delete now' : 'Delete project'}
			warning={
				mode === 'purge'
					? undefined
					: `It can be restored until ${until}, then it cannot be undone`
			}
			consequences={[
				...(changed
					? [
							`The number of accounts changed since you opened this: it is now ${String(accounts)}. Review and confirm again.`
						]
					: []),
				...consequences
			]}
			cascade={
				accounts > 0
					? {
							noun: 'end-user accounts',
							count: accounts,
							onInspect: () => {
								onClose();
								void navigate(bucketHref(bucket._id, 'users'));
							},
							inspectLabel: 'Look at the accounts first'
						}
					: undefined
			}
			busy={busy}
			onCancel={onClose}
			onConfirm={(withCascade) => void onConfirm(withCascade)}
		/>
	);
}
