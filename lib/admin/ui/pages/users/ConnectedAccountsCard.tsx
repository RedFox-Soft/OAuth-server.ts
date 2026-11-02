import { useEffect, useState } from 'react';
import { Button, Card, Table, Tag, Typography } from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { EmptyState, LoadFailed } from '../../frame/states.js';

/*
 * The accounts one person connected at the project's connected services (specs/117), and the means to disconnect
 * one for them: what support and incident response need, without the person's help. No token ever reaches here;
 * the server returns none.
 */

interface ConnectedAccountView {
	id: string;
	serviceName: string;
	upstreamId: string;
	label: string;
	scopes: string[];
	missingScopes: string[];
	connectedAt: string;
	status: 'connected' | 'needs_reconnection';
}

export function ConnectedAccountsCard({
	bucketId,
	userId,
	canDisconnect
}: {
	bucketId: string;
	userId: string;
	canDisconnect: boolean;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [accounts, setAccounts] = useState<ConnectedAccountView[] | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/users/${encodeURIComponent(userId)}/connected-accounts`;

	const [version, setVersion] = useState(0);
	const reload = () => setVersion((current) => current + 1);

	useEffect(() => {
		let live = true;
		void request<{ accounts: ConnectedAccountView[] }>('GET', base).then(
			(result) => {
				if (!live) return;
				if (result.ok) {
					setAccounts(result.data.accounts);
					setLoadError(null);
				} else {
					setLoadError(result.error.message);
				}
			}
		);
		return () => {
			live = false;
		};
	}, [base, version]);

	async function disconnect(account: ConnectedAccountView) {
		const agreed = await confirm('connectedAccount.delete', {
			target: `${account.label} (${account.serviceName})`,
			consequences: [
				'The account is forgotten here, and the provider is asked to revoke its tokens.',
				'The person can connect it again from their account page.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(account.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${account.label} disconnected.`);
		reload();
	}

	return (
		<Card title="Connected accounts">
			{loadError !== null ? (
				<LoadFailed
					reason={loadError}
					onRetry={reload}
				/>
			) : (
				<Table<ConnectedAccountView>
					size="small"
					loading={accounts === null}
					dataSource={accounts ?? []}
					pagination={false}
					rowKey="id"
					locale={{
						emptyText: (
							<EmptyState purpose="No connected accounts. A person connects one from their account page, at a service this project offers." />
						)
					}}
					columns={[
						{ title: 'Service', dataIndex: 'serviceName' },
						{
							title: 'Account',
							render: (_, account) => (
								<>
									{account.label}{' '}
									<Typography.Text
										type="secondary"
										copyable={{ text: account.upstreamId }}
									>
										{account.upstreamId}
									</Typography.Text>
								</>
							)
						},
						{
							title: 'Scopes',
							render: (_, account) => (
								<>
									{account.scopes.join(' ')}
									{account.missingScopes.length > 0 && (
										<Typography.Text type="warning">
											{' '}
											(not granted: {account.missingScopes.join(' ')})
										</Typography.Text>
									)}
								</>
							)
						},
						{
							title: 'Connected',
							dataIndex: 'connectedAt',
							render: (at: string) => new Date(at).toLocaleString()
						},
						{
							title: 'Status',
							dataIndex: 'status',
							render: (status: ConnectedAccountView['status']) =>
								status === 'connected' ? (
									<Tag color="green">Connected</Tag>
								) : (
									<Tag color="orange">Needs reconnection</Tag>
								)
						},
						{
							title: '',
							key: 'disconnect',
							render: (_: unknown, account: ConnectedAccountView) =>
								canDisconnect ? (
									<Button
										size="small"
										danger
										onClick={() => void disconnect(account)}
									>
										Disconnect
									</Button>
								) : null
						}
					]}
				/>
			)}
		</Card>
	);
}
