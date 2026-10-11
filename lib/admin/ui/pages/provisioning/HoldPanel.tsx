import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Flex, Table, Tag, Typography } from 'antd';
import { ConfirmDestruction } from '../../ConfirmDestruction.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { Link } from '../../frame/router.js';
import { userHref } from '../../frame/routes.js';
import {
	connectionsApi,
	when,
	type ConnectionView
} from './connectionShared.js';

interface Refusal {
	userId: string;
	email: string | null;
	userName: string | null;
	operation: 'deactivate' | 'delete';
	firstAt: string;
	lastAt: string;
	attempts: number;
}

type HoldRead =
	| { held: false }
	| {
			held: true;
			since: string;
			count: number;
			refused: Refusal[];
			total: number;
	  };

/*
 * A held connection: what the directory tried to do, and the three ways out (specs/084 US6).
 *
 * The list is the point. Releasing a hold applies every removal the directory retries, so the people on it
 * lose access the moment it is released; the safeguard exists so that a person decides that having seen who
 * they are. The three paths are the three reasons a directory removes many people at once — it is right, it
 * is misconfigured, or someone else holds its credential — because each one ends differently.
 */
export function HoldPanel({
	bucketId,
	connection,
	canEdit,
	onReleased,
	onRevoke,
	onDisable
}: {
	bucketId: string;
	connection: ConnectionView;
	canEdit: boolean;
	onReleased: () => void;
	onRevoke: () => void;
	onDisable: () => void;
}) {
	const feedback = useFeedback();
	const [hold, setHold] = useState<HoldRead | null>(null);
	const [failure, setFailure] = useState<string | null>(null);
	const [releasing, setReleasing] = useState(false);
	const [busy, setBusy] = useState(false);

	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchHold = useCallback(async () => {
		try {
			const result = await request<HoldRead>(
				'GET',
				`${connectionsApi(bucketId, connection.id)}/hold`
			);
			if (result.ok) {
				setHold(result.data);
				setFailure(null);
			} else {
				setFailure(result.error.message);
			}
		} finally {
			setLoading(false);
		}
	}, [bucketId, connection.id]);
	useEffect(() => {
		void fetchHold();
	}, [fetchHold]);

	async function release() {
		setBusy(true);
		try {
			const result = await request(
				'POST',
				`${connectionsApi(bucketId, connection.id)}/release`
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(
				`Hold on ${connection.displayName} released; the directory's retries will go through.`
			);
			setReleasing(false);
			onReleased();
		} finally {
			setBusy(false);
		}
	}

	if (!connection.hold) return null;
	const refused = hold?.held ? hold.refused : [];
	const total = hold?.held ? hold.total : 0;
	const more = total - refused.length;

	return (
		<Card
			title={
				<Flex
					gap={8}
					align="center"
				>
					<Tag color="red">Held</Tag>
					Deprovisioning is held
				</Flex>
			}
			styles={{ header: { background: 'var(--ant-color-error-bg)' } }}
		>
			<Flex
				vertical
				gap={16}
			>
				<Typography.Paragraph style={{ margin: 0 }}>
					Since {when(connection.hold.since)}, after {connection.hold.count}{' '}
					removals within the guard's window. Every deactivation and deletion
					from the directory is refused and retried later; creates and updates
					still go through. The people it is trying to remove keep their access
					until the hold is released.
				</Typography.Paragraph>

				<div>
					<Typography.Title
						level={5}
						style={{ marginTop: 0 }}
					>
						Who the directory is trying to remove
						{hold?.held && ` (${total})`}
					</Typography.Title>
					{failure ? (
						<Alert
							type="warning"
							showIcon
							title="The list could not be read"
							description={failure}
						/>
					) : (
						<Table<Refusal>
							size="small"
							rowKey="userId"
							loading={loading}
							dataSource={refused}
							pagination={{ pageSize: 20, hideOnSinglePage: true }}
							locale={{
								emptyText: 'No removal has been refused since the hold began.'
							}}
							columns={[
								{
									title: 'Person',
									render: (_, r) => (
										<Link href={userHref(bucketId, r.userId)}>
											{r.email ?? r.userName ?? r.userId}
										</Link>
									)
								},
								{
									title: 'Asked to',
									dataIndex: 'operation',
									render: (op: Refusal['operation']) =>
										op === 'delete' ? 'Delete' : 'Deactivate'
								},
								{ title: 'Attempts', dataIndex: 'attempts', align: 'right' },
								{
									title: 'Last attempt',
									dataIndex: 'lastAt',
									render: (v: string) => when(v)
								}
							]}
						/>
					)}
					{more > 0 && (
						<Typography.Text type="secondary">
							{more} more {more === 1 ? 'person was' : 'people were'} refused
							than are listed.
						</Typography.Text>
					)}
				</div>

				{canEdit && (
					<Flex
						vertical
						gap={12}
					>
						<Typography.Title
							level={5}
							style={{ margin: 0 }}
						>
							What to do
						</Typography.Title>
						<Flex
							justify="space-between"
							align="center"
							gap={12}
							wrap
						>
							<Typography.Text>
								<strong>These removals are expected</strong> — the directory is
								right.
							</Typography.Text>
							<Button
								danger
								onClick={() => setReleasing(true)}
							>
								Release hold…
							</Button>
						</Flex>
						<Typography.Text>
							<strong>The directory is misconfigured</strong> — fix the rule or
							the assignment there first, then release the hold. Releasing
							earlier applies the mistake.
						</Typography.Text>
						<Flex
							justify="space-between"
							align="center"
							gap={12}
							wrap
						>
							<Typography.Text>
								<strong>Someone else may hold its credential</strong> — cut it
								off.
							</Typography.Text>
							<Flex gap={8}>
								<Button onClick={onRevoke}>Go to credentials</Button>
								<Button onClick={onDisable}>Disable connection…</Button>
							</Flex>
						</Flex>
					</Flex>
				)}
			</Flex>

			<ConfirmDestruction
				open={releasing}
				title={`Release the hold on ${connection.displayName}?`}
				consequences={[
					`The directory's retried deactivations and deletions go through, and ${total === 1 ? 'that person loses' : `those ${total} people lose`} access at once.`,
					'The count starts again from zero, and the list above is cleared.'
				]}
				acknowledgement="I've checked who the directory is removing"
				word="release"
				okText="Release hold"
				busy={busy}
				onCancel={() => setReleasing(false)}
				onConfirm={() => void release()}
			/>
		</Card>
	);
}
