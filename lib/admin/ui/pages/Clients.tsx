import { useCallback, useEffect, useState } from 'react';
import { Alert, Table, Button, Space, Tag, Tooltip } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { AreaToolbar } from '../frame/AreaToolbar.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { Link, useNavigate } from '../frame/router.js';
import { applicationHref } from '../frame/routes.js';
import { atLimit, type PlanView } from '../planText.js';
import type { ClientRow, ClientView } from './applications/clientForm.js';
import { describe, lastUsedText } from './applications/blocks.js';
import { handOff } from './applications/handOff.js';
import { SituationChooser } from './applications/SituationChooser.js';

/*
 * A project's applications (specs/099, spec 107). Each one is edited on its own page; this list finds them, creates
 * them from a situation, and offers the two actions that need no page. `writable` is the project's stated `edit`
 * right; a self-registered application is listed and readable but managed through its own registration access token.
 */
export function Clients({
	bucketId,
	writable,
	plan,
	onChanged
}: {
	bucketId: string;
	writable: boolean;
	/* The plan the caller is held to (specs/102); null when nothing limits them. */
	plan?: PlanView | null;
	/* An application was added or deleted: the project's counts, and so its plan's use, changed. */
	onChanged?: () => void;
}) {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/clients`;
	const [rows, setRows] = useState<ClientRow[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailed, setLoadFailed] = useState<string | null>(null);
	const [choosing, setChoosing] = useState(false);
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchClients = useCallback(
		() =>
			request<ClientRow[]>('GET', base).then((result) => {
				if (result.ok) {
					setRows(result.data);
					setLoadFailed(null);
				} else {
					setLoadFailed(result.error.message);
				}
				setLoading(false);
			}),
		[base]
	);
	function load() {
		setLoading(true);
		return fetchClients();
	}
	useEffect(() => {
		void fetchClients();
	}, [fetchClients]);

	/*
	 * States the consequence rather than asking for confirmation of an unstated one: deleting a client
	 * destroys every credential it ever issued, and the invisible half of that is what an operator
	 * cannot otherwise see.
	 */
	async function onDelete(row: ClientView) {
		const agreed = await confirm('client.delete', {
			target: row.clientName || row.clientId,
			consequences: [
				'Its access, refresh and machine-to-machine tokens stop working immediately.',
				'Its pending codes and consent records are destroyed.',
				'Its own registration credential is destroyed.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(row.clientId)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Application deleted.');
		onChanged?.();
		await load();
	}

	/* The new secret is shown where the application's values are: on its page, once. */
	async function onRotate(row: ClientView) {
		const agreed = await confirm('client.secret.rotate', {
			target: row.clientName || row.clientId,
			consequences: [
				'The current secret stops working immediately.',
				'The application fails to authenticate until it is given the new secret.'
			]
		});
		if (!agreed) return;
		const result = await request<{ secret?: string }>(
			'POST',
			`${base}/${encodeURIComponent(row.clientId)}/secret`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Client secret rotated.');
		if (result.data.secret) {
			handOff(row.clientId, { secret: result.data.secret });
		}
		void navigate(applicationHref(bucketId, row.clientId));
	}

	function actionsFor(row: ClientRow): RowAction[] {
		const items: RowAction[] = [
			{
				key: 'open',
				label: 'Open',
				group: 'edit',
				onClick: () => void navigate(applicationHref(bucketId, row.clientId))
			}
		];
		// The server says whether there is a secret; the auth method alone answers wrongly both ways.
		if (row.hasSecret) {
			items.push({
				key: 'rotate',
				label: 'Rotate secret',
				group: 'state',
				onClick: () => void onRotate(row)
			});
		}
		items.push({
			key: 'delete',
			label: 'Delete',
			group: 'danger',
			onClick: () => void onDelete(row)
		});
		return items;
	}

	const full = atLimit(plan, 'applications');
	const newClient = (
		<Tooltip title={full ?? undefined}>
			<Button
				type="primary"
				icon={<PlusOutlined />}
				disabled={full !== null}
				onClick={() => setChoosing(true)}
			>
				New application
			</Button>
		</Tooltip>
	);

	return (
		<>
			{writable ? (
				<AreaToolbar create={newClient} />
			) : (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="These applications are read-only to you"
					description="Changing a project's applications takes membership of the team that owns it."
				/>
			)}
			{loadFailed !== null ? (
				<LoadFailed
					reason={loadFailed}
					onRetry={() => void load()}
				/>
			) : (
				<Table<ClientRow>
					rowKey="clientId"
					loading={loading}
					dataSource={rows}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No applications in this project yet. An application is an OAuth client that signs this project's people in or calls an API through this server."
								create={writable ? newClient : undefined}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'clientName',
							/*
							 * A client the server created on its own request is marked here rather than left to be
							 * inferred from the shape of its id. It cannot be inferred: a deployment's `idFactory`
							 * may issue any id, including a URL, so "looks generated" is not a distinction. What an
							 * operator needs to know is who vouched for the client — them, or nobody.
							 */
							render: (clientName: string | undefined, row: ClientRow) => (
								<Space size={4}>
									<Link href={applicationHref(bucketId, row.clientId)}>
										{clientName || row.clientId}
									</Link>
									{row.registeredDynamically ? (
										<Tag>Self-registered</Tag>
									) : null}
								</Space>
							)
						},
						{ title: 'Client ID', dataIndex: 'clientId' },
						{
							title: 'Kind',
							key: 'kind',
							render: (_: unknown, row: ClientRow) => describe(row)
						},
						{
							title: 'Last used',
							key: 'lastUsed',
							render: (_: unknown, row: ClientRow) =>
								lastUsedText(row.lastUsed ?? null)
						},
						...(writable
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, row: ClientRow) =>
											row.registeredDynamically ? null : (
												<RowActions
													name={row.clientName || row.clientId}
													items={actionsFor(row)}
												/>
											)
									}
								]
							: [])
					]}
				/>
			)}
			{writable && (
				<SituationChooser
					bucketId={bucketId}
					open={choosing}
					onClose={() => setChoosing(false)}
					siblings={rows
						.filter((row) => (row.corsOrigins?.length ?? 0) > 0)
						.map((row) => ({
							label: row.clientName || row.clientId,
							origins: row.corsOrigins ?? []
						}))}
				/>
			)}
		</>
	);
}
