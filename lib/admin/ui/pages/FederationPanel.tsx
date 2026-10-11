import { useCallback, useEffect, useState } from 'react';
import { Alert, Table, Button, Flex, Space, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { request } from '../frame/request.js';
import { RowActions } from '../frame/RowActions.js';
import { LoadFailed } from '../frame/states.js';
import { Link, useNavigate } from '../frame/router.js';
import { providerHref } from '../frame/routes.js';
import type { BucketView } from './bucketView.js';
import {
	federationApi,
	type Guidance,
	type PresentedProvider
} from './providers/providerTypes.js';
import { ProviderTiles, ProviderWizard } from './providers/ProviderWizard.js';
import {
	providerBlocks,
	useProviderActions
} from './providers/useProviderActions.js';

/*
 * A bucket's upstream identity providers: the list, and the way to connect another (specs/084). Everything
 * done to one provider after it is connected happens on its own page; this tab only lists, opens, turns off
 * and deletes.
 */
export function FederationPanel({
	bucket,
	onChanged,
	canEdit = true,
	consoleBucket = false
}: {
	bucket: BucketView;
	/*
	 * The console's own bucket (specs/080): its providers decide who can sign in to the console, so the tab
	 * says what linking and creation take there.
	 */
	consoleBucket?: boolean;
	/* The bucket's own settings depend on this list, so the parent is told when it changes. */
	onChanged?: () => void;
	/* False when the caller may read this bucket but not change it; the server would refuse every write. */
	canEdit?: boolean;
}) {
	const bucketId = bucket._id;
	const navigate = useNavigate();
	const actions = useProviderActions(bucketId, consoleBucket);
	const [rows, setRows] = useState<PresentedProvider[]>([]);
	const [guidance, setGuidance] = useState<Guidance[]>([]);
	const [bound, setBound] = useState<Map<string, string>>(new Map());
	const [loading, setLoading] = useState(true);
	const [loadFailure, setLoadFailure] = useState<string | null>(null);
	// The wizard, and the provider a tile chose to open it at (undefined: open at the first step).
	const [wizard, setWizard] = useState<{ start?: string } | null>(null);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchProviders = useCallback(async () => {
		try {
			const [providers, catalogue, connections] = await Promise.all([
				request<PresentedProvider[]>('GET', federationApi(bucketId)),
				request<{ providers?: Guidance[] }>(
					'GET',
					`${federationApi(bucketId)}/catalogue`
				),
				request<{ providerId: string; displayName: string }[]>(
					'GET',
					`/admin/api/buckets/${encodeURIComponent(bucketId)}/provisioning-connections`
				)
			]);
			/*
			 * Either of the first two failing is a failed load: without the catalogue the connect tiles and the
			 * callback address vanish, and an operator would read that as "nothing to connect". The connections
			 * only explain why Delete is unavailable, so a caller who cannot read them still gets the list.
			 */
			if (!providers.ok) {
				setLoadFailure(providers.error.message);
			} else if (!catalogue.ok) {
				setLoadFailure(catalogue.error.message);
			} else {
				setLoadFailure(null);
				setRows(providers.data);
				setGuidance(catalogue.data.providers ?? []);
				setBound(
					new Map(
						(connections.ok ? connections.data : []).map((c) => [
							c.providerId,
							c.displayName
						])
					)
				);
			}
		} finally {
			setLoading(false);
		}
	}, [bucketId]);
	useEffect(() => {
		void fetchProviders();
	}, [fetchProviders]);

	function after(done: boolean) {
		if (!done) return;
		setLoading(true);
		void fetchProviders();
		onChanged?.();
	}

	const empty = !loading && loadFailure === null && rows.length === 0;

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
					Identity providers
				</Typography.Title>
				{canEdit && !empty && (
					<Button
						icon={<PlusOutlined />}
						onClick={() => setWizard({})}
					>
						New identity provider
					</Button>
				)}
			</Space>

			<Typography.Paragraph type="secondary">
				People of this bucket can sign in through these providers.
			</Typography.Paragraph>

			{consoleBucket && (
				<Alert
					style={{ marginBottom: 12 }}
					type="warning"
					showIcon
					title="These providers sign administrators in to the console"
					description="An administrator links their identity once, by also entering their password. A provider creates new administrator accounts only when it is set to and sign-up is open on this bucket; each new account gets a personal group and never the super administrator privilege."
				/>
			)}

			{loadFailure !== null ? (
				<LoadFailed
					reason={loadFailure}
					onRetry={() => after(true)}
				/>
			) : empty ? (
				<Flex
					vertical
					gap={12}
				>
					<Typography.Text>
						No identity providers yet.
						{canEdit && ' Connect one:'}
					</Typography.Text>
					{canEdit && (
						<ProviderTiles
							guidance={guidance}
							onChoose={(id) => setWizard({ start: id })}
						/>
					)}
				</Flex>
			) : (
				<Table<PresentedProvider>
					rowKey="id"
					loading={loading}
					dataSource={rows}
					pagination={false}
					columns={[
						{
							title: 'Name',
							dataIndex: 'displayName',
							render: (name: string, row) => (
								<Link href={providerHref(bucketId, row.id)}>{name}</Link>
							)
						},
						{ title: 'Id', dataIndex: 'id' },
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
							title: 'First-time users',
							render: (_, row) =>
								row.provisioning === 'jit'
									? 'Creates accounts'
									: 'Existing only'
						},
						{
							title: 'Email domains',
							render: (_, row) =>
								row.allowedEmailDomains.length > 0
									? row.allowedEmailDomains.join(', ')
									: 'Any'
						},
						{
							title: '',
							key: 'actions',
							render: (_: unknown, row: PresentedProvider) => {
								const connection = bound.get(row.id);
								const blocks = providerBlocks(
									bucket,
									row,
									connection ? { displayName: connection } : null
								);
								return (
									<RowActions
										name={row.displayName}
										items={[
											{
												key: 'open',
												label: 'Open',
												group: 'edit',
												onClick: () =>
													void navigate(providerHref(bucketId, row.id))
											},
											...(canEdit
												? [
														row.enabled
															? {
																	key: 'disable',
																	label: 'Disable…',
																	group: 'state' as const,
																	blocked: blocks.disable,
																	onClick: () =>
																		void actions
																			.setEnabled(row, false)
																			.then(after)
																}
															: {
																	key: 'enable',
																	label: 'Enable',
																	group: 'state' as const,
																	onClick: () =>
																		void actions
																			.setEnabled(row, true)
																			.then(after)
																},
														{
															key: 'delete',
															label: 'Delete…',
															group: 'danger' as const,
															blocked: blocks.remove,
															onClick: () =>
																void actions.remove(row).then(after)
														}
													]
												: [])
										]}
									/>
								);
							}
						}
					]}
				/>
			)}

			{wizard && (
				<ProviderWizard
					bucketId={bucketId}
					guidance={guidance}
					registrationOpen={bucket.registrationOpen}
					consoleBucket={consoleBucket}
					start={wizard.start}
					onClose={() => setWizard(null)}
				/>
			)}
		</div>
	);
}
