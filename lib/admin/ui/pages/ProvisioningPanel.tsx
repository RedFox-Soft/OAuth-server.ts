import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Flex,
	Space,
	Table,
	Tag,
	Tooltip,
	Typography
} from 'antd';
import { ApiOutlined, PlusOutlined } from '@ant-design/icons';
import type { FederationProvider } from '../../../federation/types.js';
import { providerMark } from '../../../interactions/providerMark.js';
import { request } from '../frame/request.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { LoadFailed } from '../frame/states.js';
import { Link, useNavigate } from '../frame/router.js';
import { connectionHref } from '../frame/routes.js';
import type { BucketView } from './bucketView.js';
import {
	WARNING_LABELS,
	connectionsApi,
	when,
	type ConnectionView,
	type ConnectionWarning
} from './provisioning/connectionShared.js';
import { ConnectionWizard } from './provisioning/ConnectionWizard.js';
import {
	deleteBlock,
	useConnectionActions
} from './provisioning/useConnectionActions.js';
import { federationApi, type Guidance } from './providers/providerTypes.js';
import { OTHER_PROVIDER, ProviderWizard } from './providers/ProviderWizard.js';

export type { ConnectionView };

/*
 * A bucket's SCIM provisioning connections: the directory (Entra ID, Okta, …) that creates, changes and
 * removes this bucket's people (specs/084). The tab lists them and creates them; everything done to one
 * connection after that happens on its own page, the one the hold email links to.
 *
 * The list is handed up through `onConnections`, because the user table beside it names the connection that
 * manages each person.
 */
export function ProvisioningPanel({
	bucket,
	refreshKey,
	onConnections,
	onChanged,
	canEdit = true
}: {
	bucket: BucketView;
	/* Bumped by the parent when something this panel shows changed elsewhere — a provider, a user's owner. */
	refreshKey?: number;
	/* Must be stable (a state setter): it is a dependency of the fetch. */
	onConnections?: (connections: ConnectionView[]) => void;
	onChanged?: () => void;
	/* False when the caller may read this bucket but not change it; the server would refuse every write. */
	canEdit?: boolean;
}) {
	const bucketId = bucket._id;
	const navigate = useNavigate();
	const actions = useConnectionActions(bucketId);
	const [rows, setRows] = useState<ConnectionView[]>([]);
	const [providers, setProviders] = useState<FederationProvider[]>([]);
	const [guidance, setGuidance] = useState<Guidance[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailure, setLoadFailure] = useState<string | null>(null);
	const [wizard, setWizard] = useState(false);
	// A provider connected from the empty state: the provider wizard, opened at the tile chosen.
	const [connectProvider, setConnectProvider] = useState<string | null>(null);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchConnections = useCallback(async () => {
		try {
			const [connections, federation, catalogue] = await Promise.all([
				request<ConnectionView[]>('GET', connectionsApi(bucketId)),
				request<FederationProvider[]>('GET', federationApi(bucketId)),
				request<{ providers?: Guidance[] }>(
					'GET',
					`${federationApi(bucketId)}/catalogue`
				)
			]);
			/*
			 * Either of the first two failing is a failed load: without the providers, "New connection" would say
			 * every provider already has one, which is a wrong answer rather than no answer.
			 */
			if (!connections.ok) {
				setLoadFailure(connections.error.message);
			} else if (!federation.ok) {
				setLoadFailure(federation.error.message);
			} else {
				setLoadFailure(null);
				setRows(connections.data);
				setProviders(federation.data);
				setGuidance(catalogue.ok ? (catalogue.data.providers ?? []) : []);
				onConnections?.(connections.data);
			}
		} finally {
			setLoading(false);
		}
	}, [bucketId, onConnections]);
	useEffect(() => {
		void fetchConnections();
	}, [fetchConnections, refreshKey]);

	function after(done: boolean) {
		if (!done) return;
		setLoading(true);
		void fetchConnections();
		onChanged?.();
	}

	/* A provider holds at most one connection, so the wizard never offers one the server would refuse. */
	const bound = new Set(rows.map((row) => row.providerId));
	const free = providers.filter((p) => !bound.has(p.id));
	const providerName = (id: string) =>
		providers.find((p) => p.id === id)?.displayName ?? id;

	function actionsFor(row: ConnectionView): RowAction[] {
		return [
			{
				key: 'open',
				label: row.hold ? 'Review hold' : 'Open',
				group: 'edit',
				onClick: () => void navigate(connectionHref(bucketId, row.id))
			},
			...(canEdit
				? [
						row.enabled
							? {
									key: 'disable',
									label: 'Disable…',
									group: 'state' as const,
									onClick: () => void actions.setEnabled(row, false).then(after)
								}
							: {
									key: 'enable',
									label: 'Enable',
									group: 'state' as const,
									onClick: () => void actions.setEnabled(row, true).then(after)
								},
						{
							key: 'delete',
							label: 'Delete…',
							group: 'danger' as const,
							blocked: deleteBlock(row),
							onClick: () => void actions.remove(row).then(after)
						}
					]
				: [])
		];
	}

	const noProvider = !loading && loadFailure === null && free.length === 0;

	return (
		<div style={{ marginTop: 8 }}>
			<Space
				style={{ marginBottom: 12 }}
				align="center"
			>
				<Typography.Title
					level={4}
					style={{ margin: 0 }}
				>
					Provisioning (SCIM)
				</Typography.Title>
				{canEdit && !noProvider && (
					<Button
						icon={<PlusOutlined />}
						disabled={loading || loadFailure !== null}
						onClick={() => setWizard(true)}
					>
						New provisioning connection
					</Button>
				)}
			</Space>

			<Typography.Paragraph type="secondary">
				A connection lets a directory create, update and remove this project's
				people. Each one is bound to an identity provider, which then signs in
				existing accounts only, so a person is never created twice.
			</Typography.Paragraph>

			{canEdit && noProvider && (
				<Alert
					style={{ marginBottom: 12 }}
					type="info"
					showIcon
					title={
						providers.length === 0
							? 'A directory needs an identity provider its people sign in with'
							: 'Every identity provider of this project already has a connection'
					}
					description={
						<Flex
							gap={8}
							wrap
							style={{ marginTop: 8 }}
						>
							{guidance.some(
								(g) => g.catalogueId === 'microsoft' && !g.alreadyConnected
							) && (
								<Button
									icon={providerMark('microsoft')}
									onClick={() => setConnectProvider('microsoft')}
								>
									Connect Microsoft
								</Button>
							)}
							<Button
								icon={<ApiOutlined />}
								onClick={() => setConnectProvider(OTHER_PROVIDER)}
							>
								Connect another OIDC provider…
							</Button>
						</Flex>
					}
				/>
			)}

			{loadFailure !== null ? (
				<LoadFailed
					reason={loadFailure}
					onRetry={() => after(true)}
				/>
			) : (
				<Table<ConnectionView>
					rowKey="id"
					loading={loading}
					dataSource={rows}
					pagination={false}
					locale={{
						emptyText: loading
							? ' '
							: "No provisioning connections yet. No directory creates or removes this project's people."
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'displayName',
							render: (name: string, row) => (
								<Space size={4}>
									<Link href={connectionHref(bucketId, row.id)}>{name}</Link>
									{row.hold && (
										<Tooltip
											title={`Safeguard tripped ${when(row.hold.since)} — open the connection to review the hold`}
										>
											<Tag color="red">Deprovisioning held</Tag>
										</Tooltip>
									)}
								</Space>
							)
						},
						{
							title: 'Signs in with',
							dataIndex: 'providerId',
							render: (id: string) => providerName(id)
						},
						{
							title: 'Status',
							dataIndex: 'enabled',
							render: (enabled: boolean) => (
								<Tag color={enabled ? 'green' : 'default'}>
									{enabled ? 'Enabled' : 'Disabled'}
								</Tag>
							)
						},
						{
							title: 'Manages',
							dataIndex: 'managedUsers',
							render: (n: number) => `${n} ${n === 1 ? 'user' : 'users'}`
						},
						{
							title: 'Last request',
							dataIndex: 'lastUsedAt',
							render: (value: string | null) => when(value)
						},
						{
							title: 'Warnings',
							dataIndex: 'warnings',
							render: (warnings: ConnectionWarning[]) =>
								warnings.length === 0 ? (
									<Typography.Text type="secondary">—</Typography.Text>
								) : (
									<Space
										size={4}
										wrap
									>
										{warnings.map((w) => (
											<Tag
												key={w}
												color="orange"
											>
												{WARNING_LABELS[w]}
											</Tag>
										))}
									</Space>
								)
						},
						{
							title: '',
							key: 'actions',
							render: (_: unknown, row: ConnectionView) => (
								<RowActions
									name={row.displayName}
									items={actionsFor(row)}
								/>
							)
						}
					]}
				/>
			)}

			{wizard && (
				<ConnectionWizard
					bucketId={bucketId}
					bucketName={bucket.name}
					providers={free}
					onClose={() => setWizard(false)}
				/>
			)}
			{connectProvider && (
				<ProviderWizard
					bucketId={bucketId}
					guidance={guidance}
					registrationOpen={bucket.registrationOpen}
					consoleBucket={false}
					start={connectProvider}
					onClose={() => setConnectProvider(null)}
				/>
			)}
		</div>
	);
}
