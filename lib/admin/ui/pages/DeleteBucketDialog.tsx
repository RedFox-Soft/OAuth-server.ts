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
 * The account count is read when the dialog opens, never taken from a list: it is the number the operator
 * consents to destroy, and the server refuses the deletion if it changed (`expect`). When it did, the dialog
 * reads it again, unticks the consent by starting over, and says so — the operator agrees to the new number,
 * not the old one.
 */
export function DeleteBucketDialog({
	bucket,
	onClose,
	onDeleted
}: {
	bucket: { _id: string; name: string };
	onClose: () => void;
	onDeleted: (accountsDestroyed: number) => void;
}) {
	const feedback = useFeedback();
	const navigate = useNavigate();
	const [accounts, setAccounts] = useState<number | null>(null);
	const [changed, setChanged] = useState(false);
	// Bumped to start the dialog over, consent unticked, when the count moved under the operator.
	const [round, setRound] = useState(0);
	const [busy, setBusy] = useState(false);
	const summaryPath = `/admin/api/buckets/${encodeURIComponent(bucket._id)}/summary`;
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
		const result = await request<{ endUsersDestroyed?: number }>(
			'DELETE',
			`/admin/api/buckets/${encodeURIComponent(bucket._id)}${qs ? `?${qs}` : ''}`
		);
		setBusy(false);
		if (result.ok) {
			onDeleted(result.data.endUsersDestroyed ?? 0);
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

	return (
		<ConfirmDestruction
			key={round}
			open
			title={`Delete ${bucket.name}?`}
			okText="Delete bucket"
			consequences={[
				...(changed
					? [
							`The number of accounts changed since you opened this: it is now ${String(accounts)}. Review and confirm again.`
						]
					: []),
				'The bucket is gone permanently. There is nothing left to inspect or restore.',
				'Its sign-in address stops answering, and every token it minted stops being issued from it.'
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
