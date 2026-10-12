import { useEffect, useState } from 'react';
import { Button, Card, Table, Tag, Tooltip, Typography } from 'antd';
import { QuestionCircleOutlined } from '@ant-design/icons';
import { useConfirm } from '../../frame/confirm.js';
import { useFeedback } from '../../frame/feedback.js';
import { request } from '../../frame/request.js';
import { usersApi, type EndUser } from './endUser.js';

/* GET …/users/:uid/sessions (specs/089): derived from the person's grants, names and times only. */
interface ApplicationSession {
	clientId: string | null;
	clientName: string | null;
	signedInAt: string | null;
	lastTokenAt: string | null;
	offline: boolean;
}

const when = (iso: string | null) =>
	iso ? new Date(iso).toLocaleString() : '—';

/*
 * Where the person is signed in, and a way to end one application's access without ending the rest (specs/089
 * US3). No network address, browser or device: the server stores none, and the card does not pretend otherwise.
 */
export function SessionsCard({
	bucketId,
	user,
	canManage,
	refreshKey
}: {
	bucketId: string;
	user: EndUser;
	canManage: boolean;
	/* A new value after the page reloads the person (Sign out everywhere, a lock): the list is read again. */
	refreshKey?: unknown;
}) {
	const confirm = useConfirm();
	const feedback = useFeedback();
	const [rows, setRows] = useState<ApplicationSession[] | null>(null);
	const [failed, setFailed] = useState<string | null>(null);
	const api = `${usersApi(bucketId, user._id)}/sessions`;

	// Bumped after this card's own sign-out, as `refreshKey` is by the page.
	const [tick, setTick] = useState(0);

	useEffect(() => {
		let current = true;
		void request<{ applications: ApplicationSession[] }>('GET', api).then(
			(result) => {
				if (!current) return;
				if (result.ok) {
					setRows(result.data.applications);
					setFailed(null);
				} else {
					setFailed(result.error.message);
				}
			}
		);
		return () => {
			current = false;
		};
	}, [api, refreshKey, tick]);

	async function signOutOf(row: ApplicationSession) {
		if (!row.clientId) return;
		const app = row.clientName ?? row.clientId;
		const agreed = await confirm('user.application.signout', {
			target: app,
			consequences: [
				`${user.email} is signed out of ${app}, and its tokens for them stop working — offline access included.`,
				'Other applications are not affected.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'POST',
			`${api}/${encodeURIComponent(row.clientId)}/sign-out`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`Signed out of ${app}.`);
		setTick((n) => n + 1);
	}

	return (
		<Card title="Sessions">
			{failed !== null ? (
				<Typography.Text type="danger">{failed}</Typography.Text>
			) : (
				<Table<ApplicationSession>
					rowKey={(row) => row.clientId ?? '(no application)'}
					loading={rows === null}
					dataSource={rows ?? []}
					pagination={false}
					size="small"
					locale={{
						emptyText: rows ? 'Not signed in to any application.' : ' '
					}}
					columns={[
						{
							title: 'Application',
							key: 'app',
							render: (_: unknown, row: ApplicationSession) =>
								row.clientId ? (
									<>
										{row.clientName ?? <code>{row.clientId}</code>}{' '}
										{row.offline && <Tag>Offline access</Tag>}
									</>
								) : (
									<Typography.Text type="secondary">
										Signed in, no application yet
									</Typography.Text>
								)
						},
						{
							title: 'Signed in',
							key: 'signedIn',
							render: (_: unknown, row: ApplicationSession) =>
								when(row.signedInAt)
						},
						{
							title: (
								<Tooltip title="When the app last received a token here. A token it checks by itself is never seen by this server.">
									Last token issued <QuestionCircleOutlined />
								</Tooltip>
							),
							key: 'lastToken',
							render: (_: unknown, row: ApplicationSession) =>
								when(row.lastTokenAt)
						},
						{
							title: '',
							key: 'actions',
							render: (_: unknown, row: ApplicationSession) =>
								canManage && row.clientId ? (
									<Button
										size="small"
										onClick={() => void signOutOf(row)}
									>
										Sign out of this app
									</Button>
								) : null
						}
					]}
				/>
			)}
		</Card>
	);
}
