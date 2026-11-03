import { useEffect, useState } from 'react';
import { Button, Card, Table, Tag, Typography } from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { EmptyState, LoadFailed } from '../../frame/states.js';
import {
	applicationName,
	type ExchangeCandidate
} from '../applications/exchange.js';

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
	/* The applications the person allowed to use this account, and when each last did (specs/118). */
	agents: { clientId: string; lastUsedAt?: string }[];
	broken?: { reason: BreakReason; at: string };
	lastRefreshedAt?: string;
}

type BreakReason =
	| 'refresh_rejected'
	| 'refresh_unsaved'
	| 'identity_changed'
	| 'no_refresh_token';

const BREAK_TEXT: Record<BreakReason, string> = {
	refresh_rejected:
		'Needs reconnecting: the provider rejected its refresh token',
	refresh_unsaved:
		'Needs reconnecting: the refreshed tokens could not be saved',
	identity_changed: 'Needs reconnecting: the provider returned another account',
	no_refresh_token:
		'Needs reconnecting: it was connected at sign-in without a refresh token, and its token expired'
};

function when(at: string): string {
	return new Date(at).toLocaleString();
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
	const [applications, setApplications] = useState<ExchangeCandidate[]>([]);
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

	// Only to name the applications; without it each is shown by its client id.
	useEffect(() => {
		let live = true;
		void request<ExchangeCandidate[]>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucketId)}/clients`
		).then((result) => {
			if (live && result.ok) setApplications(result.data);
		});
		return () => {
			live = false;
		};
	}, [bucketId]);

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
							title: 'Applications allowed',
							render: (_, account) =>
								account.agents.length === 0 ? (
									<Typography.Text type="secondary">None</Typography.Text>
								) : (
									<ul style={{ margin: 0, paddingInlineStart: 16 }}>
										{account.agents.map((agent) => (
											<li key={agent.clientId}>
												{applicationName(agent.clientId, applications)}{' '}
												<Typography.Text type="secondary">
													{agent.lastUsedAt
														? `last used ${when(agent.lastUsedAt)}`
														: 'not used yet'}
												</Typography.Text>
											</li>
										))}
									</ul>
								)
						},
						{
							title: 'Connected',
							render: (_, account) => (
								<>
									{when(account.connectedAt)}
									{account.lastRefreshedAt && (
										<div>
											<Typography.Text type="secondary">
												Last refreshed {when(account.lastRefreshedAt)}
											</Typography.Text>
										</div>
									)}
								</>
							)
						},
						{
							title: 'Status',
							render: (_, account) =>
								account.status === 'connected' ? (
									<Tag color="green">Connected</Tag>
								) : (
									<>
										<Tag color="orange">Needs reconnection</Tag>
										{account.broken && (
											<div>
												<Typography.Text type="secondary">
													{`${BREAK_TEXT[account.broken.reason]} (${when(account.broken.at)})`}
												</Typography.Text>
											</div>
										)}
									</>
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
