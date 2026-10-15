import { useState, type ReactNode } from 'react';
import { Alert, Button, Space } from 'antd';
import { useConfirm } from '../frame/confirm.js';
import { useFeedback } from '../frame/feedback.js';
import { request } from '../frame/request.js';
import { useNavigate } from '../frame/router.js';
import { DeleteBucketDialog } from './DeleteBucketDialog.js';
import type { BucketDeletionView } from './bucketView.js';

function plural(n: number, one: string, many: string): string {
	return `${String(n)} ${n === 1 ? one : many}`;
}

type Named = { _id: string; name: string };

/*
 * Restore and Delete now for a bucket scheduled for deletion (specs/090), shared by the banner on the bucket's
 * pages and the bucket list's menu, so both ask the same question and say the same thing afterwards.
 *
 * `dialog` must be rendered by the caller: Delete now is a typed-word dialog of its own, not a question.
 */
export function useScheduledActions({
	onRestored,
	onDeleted
}: {
	onRestored: () => void;
	onDeleted: () => void;
}): {
	restore: (bucket: Named) => Promise<void>;
	deleteNow: (bucket: Named) => void;
	dialog: ReactNode;
} {
	const confirm = useConfirm();
	const feedback = useFeedback();
	const [purging, setPurging] = useState<Named | null>(null);

	async function restore(bucket: Named) {
		const ok = await confirm('bucket.restore', {
			target: bucket.name,
			consequences: [
				'It answers again at once. People who were signed in stay signed in.',
				'A directory that only sends changes may need a manual resync for what it sent meanwhile.'
			]
		});
		if (!ok) return;
		const result = await request(
			'POST',
			`/admin/api/projects/${encodeURIComponent(bucket._id)}/restore`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${bucket.name} restored.`);
		onRestored();
	}

	const dialog = purging ? (
		<DeleteBucketDialog
			bucket={purging}
			mode="purge"
			onClose={() => setPurging(null)}
			onDeleted={({ accounts }) => {
				setPurging(null);
				feedback.done(
					accounts > 0
						? `Project ${purging.name} deleted, with ${plural(accounts, 'account', 'accounts')}.`
						: `Project ${purging.name} deleted.`
				);
				onDeleted();
			}}
		/>
	) : null;

	return { restore, deleteNow: setPurging, dialog };
}

/*
 * Above every area of a scheduled bucket, so nobody reads its users or edits nothing on it without knowing the
 * bucket is off and when it goes. The buttons are offered only to whoever may delete it, which is who may undo it.
 */
export function ScheduledBanner({
	bucket,
	canDelete,
	onRestored
}: {
	bucket: { _id: string; name: string; deletion: BucketDeletionView };
	canDelete: boolean;
	onRestored: () => void;
}) {
	const navigate = useNavigate();
	const { restore, deleteNow, dialog } = useScheduledActions({
		onRestored,
		onDeleted: () => void navigate('/admin/projects', { replace: true })
	});
	const stopped = new Date(bucket.deletion.scheduledAt).toLocaleDateString();
	const purge = new Date(bucket.deletion.purgeAt).toLocaleDateString();
	return (
		<>
			<Alert
				type="warning"
				showIcon
				title={`This project stopped answering on ${stopped} and will be deleted on ${purge}.`}
				description="People can't sign in and apps can't get tokens. Nothing in it has been deleted yet, and nothing can be changed until it is restored."
				action={
					canDelete ? (
						<Space>
							<Button onClick={() => void restore(bucket)}>Restore</Button>
							<Button
								danger
								onClick={() => deleteNow(bucket)}
							>
								Delete now…
							</Button>
						</Space>
					) : undefined
				}
			/>
			{dialog}
		</>
	);
}
