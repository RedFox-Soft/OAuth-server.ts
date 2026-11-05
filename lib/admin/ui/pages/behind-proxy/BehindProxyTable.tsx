import { useCallback, useEffect, useState } from 'react';
import { Button, Card, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import { Link } from '../../frame/router.js';
import { behindProxyHref } from '../../frame/routes.js';
import { EmptyState, LoadFailed } from '../../frame/states.js';
import { NewBehindProxyModal } from './CreateForm.js';
import {
	behindProxyApi,
	hostOfAddress,
	whenText,
	whoText,
	type AppView
} from './appView.js';

/*
 * A project's apps behind the operator's proxy (specs/122 FR-031): a table of their own beside the OAuth
 * applications, because they are not OAuth clients — no client list, no plan's application limit. Each opens on its
 * own page; this list finds them and creates them.
 */
export function BehindProxyTable({
	bucketId,
	writable
}: {
	bucketId: string;
	writable: boolean;
}) {
	const [apps, setApps] = useState<AppView[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailed, setLoadFailed] = useState<string | null>(null);
	const [creating, setCreating] = useState(false);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchApps = useCallback(
		() =>
			request<{ apps: AppView[] }>('GET', behindProxyApi(bucketId)).then(
				(result) => {
					if (result.ok) {
						setApps(result.data.apps);
						setLoadFailed(null);
					} else {
						setLoadFailed(result.error.message);
					}
					setLoading(false);
				}
			),
		[bucketId]
	);
	useEffect(() => {
		void fetchApps();
	}, [fetchApps]);

	const newApp = (
		<Button
			icon={<PlusOutlined />}
			onClick={() => setCreating(true)}
		>
			New app behind your proxy
		</Button>
	);

	return (
		<Card
			title="Apps behind your proxy"
			extra={writable && apps.length > 0 ? newApp : undefined}
			style={{ marginTop: 24 }}
		>
			{loadFailed !== null ? (
				<LoadFailed
					reason={loadFailed}
					onRetry={() => {
						setLoading(true);
						void fetchApps();
					}}
				/>
			) : (
				<Table<AppView>
					rowKey="id"
					loading={loading}
					dataSource={apps}
					pagination={false}
					scroll={{ x: 'max-content' }}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No apps behind your proxy yet. Put sign-in in front of a web app that has none of its own: your proxy asks this project who may open it."
								create={writable ? newApp : undefined}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'name',
							render: (name: string, app) => (
								<Link href={behindProxyHref(bucketId, app.id)}>{name}</Link>
							)
						},
						{
							title: 'Address',
							dataIndex: 'address',
							render: (address: string) => (
								<Typography.Text code>{hostOfAddress(address)}</Typography.Text>
							)
						},
						{
							title: 'Who can open it',
							key: 'who',
							render: (_: unknown, app) => {
								const root = app.rules.find((rule) => rule.path === '/');
								return (
									<Space size={4}>
										{whoText(root?.who ?? null, () => null)}
										{root?.who.kind === 'public' && <Tag>Public</Tag>}
									</Space>
								);
							}
						},
						{
							title: 'Last asked',
							key: 'lastAsked',
							render: (_: unknown, app) =>
								app.lastAskedAt ? (
									whenText(app.lastAskedAt)
								) : (
									<Typography.Text type="secondary">Not yet</Typography.Text>
								)
						}
					]}
				/>
			)}
			{writable && (
				<NewBehindProxyModal
					bucketId={bucketId}
					open={creating}
					onClose={() => setCreating(false)}
				/>
			)}
		</Card>
	);
}
