import { useEffect, useState } from 'react';
import { Modal, List, Button, Typography, Popconfirm, message } from 'antd';
import type { FederatedIdentity } from '../../../federation/types.js';

/*
 * One account's upstream identities, and the means to sever one.
 *
 * A modal on the bucket's user table rather than a page of its own: there is no user-detail page in this
 * console, and `BucketDetail` is the per-bucket user surface.
 */
export function UserIdentities({
	bucketId,
	user,
	onClose
}: {
	bucketId: string;
	user: { _id: string; email: string } | null;
	onClose: () => void;
}) {
	const [links, setLinks] = useState<FederatedIdentity[]>([]);
	const [loading, setLoading] = useState(false);

	const base = user
		? `/admin/api/buckets/${encodeURIComponent(bucketId)}/users/${encodeURIComponent(user._id)}/identities`
		: '';

	async function load() {
		if (!user) return;
		setLoading(true);
		try {
			const res = await fetch(base);
			setLinks(res.ok ? await res.json() : []);
		} finally {
			setLoading(false);
		}
	}

	useEffect(() => {
		void load();
	}, [user?._id]);

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
			<List<FederatedIdentity>
				loading={loading}
				dataSource={links}
				locale={{ emptyText: 'This account has no linked identities.' }}
				rowKey={(link) => `${link.providerId}:${link.sub}`}
				renderItem={(link) => (
					<List.Item
						actions={[
							<Popconfirm
								key="remove"
								title="Remove this link?"
								onConfirm={async () => {
									const res = await fetch(
										`${base}/${encodeURIComponent(link.providerId)}`,
										{ method: 'DELETE' }
									);
									if (!res.ok) {
										const detail = (await res.json().catch(() => null)) as {
											message?: string;
										} | null;
										message.error(
											detail?.message ?? `request failed (${res.status})`
										);
										return;
									}
									await load();
								}}
							>
								<Button
									size="small"
									danger
								>
									Remove
								</Button>
							</Popconfirm>
						]}
					>
						<List.Item.Meta
							title={link.providerId}
							description={
								// The subject is the provider's own identifier for this person; an operator
								// diagnosing a duplicate account needs to see it.
								`subject ${link.sub}${
									link.linkedAt
										? ` — linked ${new Date(link.linkedAt).toLocaleString()}`
										: ''
								}`
							}
						/>
					</List.Item>
				)}
			/>
		</Modal>
	);
}
