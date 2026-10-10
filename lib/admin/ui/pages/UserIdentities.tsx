import { useCallback, useEffect, useState } from 'react';
import { Modal, List, Button, Typography, Popconfirm } from 'antd';
import type { FederatedIdentity } from '../../../federation/types.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { ACTIONS } from '../frame/actions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';

const REMOVE_IDENTITY = ACTIONS['user.identity.remove'];

/*
 * One account's upstream identities, and the means to sever one.
 *
 * A modal on the bucket's user table rather than a page of its own: there is no user-detail page in this
 * console, and `BucketDetail` is the per-bucket user surface.
 *
 * `canRemove` is the bucket's `manageUsers`: without it the links are shown and nothing is offered.
 */
export function UserIdentities({
	bucketId,
	user,
	canRemove = true,
	onClose
}: {
	bucketId: string;
	user: { _id: string; email: string } | null;
	canRemove?: boolean;
	onClose: () => void;
}) {
	const feedback = useFeedback();
	const [links, setLinks] = useState<FederatedIdentity[]>([]);
	/*
	 * Whose links `links` holds. The modal stays mounted while the account it shows changes, so this is
	 * what says the list is still loading on opening — without it, the previous account's links showed
	 * under the new account's name until the fetch returned.
	 */
	const [linksOf, setLinksOf] = useState<string | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [reloading, setReloading] = useState(false);

	const userId = user?._id;
	const base = userId
		? `/admin/api/buckets/${encodeURIComponent(bucketId)}/users/${encodeURIComponent(userId)}/identities`
		: '';

	const fetchLinks = useCallback(async () => {
		if (!userId) return;
		try {
			const result = await request<FederatedIdentity[]>('GET', base);
			if (result.ok) {
				setLinks(result.data);
				setLoadError(null);
			} else {
				setLinks([]);
				setLoadError(result.error.message);
			}
			setLinksOf(userId);
		} finally {
			setReloading(false);
		}
	}, [base, userId]);
	function load() {
		setReloading(true);
		return fetchLinks();
	}

	useEffect(() => {
		void fetchLinks();
	}, [fetchLinks]);

	async function onRemove(link: FederatedIdentity) {
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(link.providerId)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`Linked identity ${link.providerId} removed.`);
		await load();
	}

	const current = userId !== undefined && linksOf === userId;
	const loading = reloading || (userId !== undefined && !current);

	return (
		<Modal
			open={Boolean(user)}
			title={user ? `Linked identities — ${user.email}` : ''}
			footer={null}
			onCancel={onClose}
		>
			<Typography.Paragraph type="secondary">
				Removing a link does not delete the account. The next sign-in through
				that provider is treated as a first-time sign-in and re-checked against
				the provider's current settings.
			</Typography.Paragraph>
			{current && loadError !== null ? (
				<LoadFailed
					reason={loadError}
					onRetry={() => void load()}
				/>
			) : (
				<List<FederatedIdentity>
					loading={loading}
					dataSource={current ? links : []}
					locale={{
						emptyText: (
							<EmptyState purpose="This account has no linked identities." />
						)
					}}
					rowKey={(link) => `${link.providerId}:${link.sub}`}
					renderItem={(link) => (
						<List.Item
							actions={
								canRemove
									? [
											/*
											 * Asked in place: this list is already inside a dialog, and a second
											 * modal over it is the stacking the console avoids.
											 */
											<Popconfirm
												key="remove"
												title={REMOVE_IDENTITY.title(link.providerId)}
												okText={REMOVE_IDENTITY.okText}
												onConfirm={() => onRemove(link)}
											>
												<Button size="small">Remove</Button>
											</Popconfirm>
										]
									: []
							}
						>
							<List.Item.Meta
								title={link.providerId}
								description={
									// The subject is the provider's own identifier for this person; an operator
									// diagnosing a duplicate account needs to see it.
									`subject ${link.sub} — linked ${new Date(link.linkedAt).toLocaleString()}`
								}
							/>
						</List.Item>
					)}
				/>
			)}
		</Modal>
	);
}
