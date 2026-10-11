import { useCallback, useEffect, useState } from 'react';
import { Button, Table, Typography } from 'antd';
import type { FederatedIdentity } from '../../../federation/types.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { EmptyState, LoadFailed } from '../frame/states.js';

/*
 * One account's upstream identities, and the means to sever one — on the person's Sign-in methods tab
 * (specs/082), where it used to be a dialog off the users table.
 *
 * Removing a link does not delete the account. When it is the only way the person can sign in — no
 * password they know of, or password sign-in off for the bucket — the question says so and is asked as a
 * danger question: after it, nobody can sign in as them until an administrator gives them a way back.
 */
export function UserIdentityLinks({
	bucketId,
	user,
	canRemove,
	passwordUsable,
	onChanged
}: {
	bucketId: string;
	user: { _id: string; email: string };
	canRemove: boolean;
	/* Whether a password could still sign them in: set, or unknown, and accepted by the bucket. */
	passwordUsable: boolean;
	onChanged?: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [links, setLinks] = useState<FederatedIdentity[] | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);

	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}/users/${encodeURIComponent(user._id)}/identities`;

	const fetchLinks = useCallback(async () => {
		try {
			const result = await request<FederatedIdentity[]>('GET', base);
			if (result.ok) {
				setLinks(result.data);
				setLoadError(null);
			} else {
				setLoadError(result.error.message);
			}
		} finally {
			setLoading(false);
		}
	}, [base]);
	function load() {
		setLoading(true);
		return fetchLinks();
	}
	useEffect(() => {
		void fetchLinks();
	}, [fetchLinks]);

	async function onRemove(link: FederatedIdentity) {
		const last = (links?.length ?? 0) <= 1 && !passwordUsable;
		const consequences = [
			'The account is kept. Their next sign-in through this provider is treated as a first one and checked against its current settings.'
		];
		const agreed = last
			? await confirm('user.identity.removeOnly', {
					target: link.providerId,
					consequences: [
						`It is the only way ${user.email} can sign in: nobody can, until an administrator sets a password or the provider links them again.`,
						...consequences
					]
				})
			: await confirm('user.identity.remove', {
					target: link.providerId,
					consequences
				});
		if (!agreed) return;
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
		onChanged?.();
	}

	if (loadError !== null) {
		return (
			<LoadFailed
				reason={loadError}
				onRetry={() => void load()}
			/>
		);
	}

	return (
		<Table<FederatedIdentity>
			size="small"
			loading={loading}
			dataSource={links ?? []}
			pagination={false}
			rowKey={(link) => `${link.providerId}:${link.sub}`}
			locale={{
				emptyText: (
					<EmptyState purpose="No linked identities. One is added when they sign in through an identity provider of this bucket." />
				)
			}}
			columns={[
				{ title: 'Provider', dataIndex: 'providerId' },
				{
					// The provider's own identifier for this person; an operator diagnosing a duplicate needs it.
					title: 'Subject',
					dataIndex: 'sub',
					render: (sub: string) => (
						<Typography.Text copyable>{sub}</Typography.Text>
					)
				},
				{
					title: 'Linked',
					dataIndex: 'linkedAt',
					render: (at: string) => new Date(at).toLocaleString()
				},
				{
					title: '',
					key: 'remove',
					render: (_: unknown, link: FederatedIdentity) =>
						canRemove ? (
							<Button
								size="small"
								onClick={() => void onRemove(link)}
							>
								Remove
							</Button>
						) : null
				}
			]}
		/>
	);
}
