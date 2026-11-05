import { useCallback, useEffect, useState } from 'react';
import { Alert, Skeleton, Tag, Typography } from 'antd';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';
import { behindProxyHref, bucketHref } from '../../frame/routes.js';
import { request } from '../../frame/request.js';
import { bucketCan } from '../../frame/can.js';
import type { BucketView } from '../bucketView.js';
import { ScheduledBanner } from '../ScheduledBanner.js';
import { groupsApi, type GroupView } from '../groups/groupShared.js';
import { behindProxyApi, type AppView } from './appView.js';
import { ConnectTab } from './ConnectTab.js';
import { AccessTab } from './AccessTab.js';
import { SettingsTab } from './SettingsTab.js';

export type BehindProxyTab = 'connect' | 'access' | 'settings';

const TABS: { key: BehindProxyTab; label: string }[] = [
	{ key: 'connect', label: 'Connect' },
	{ key: 'access', label: 'Access' },
	{ key: 'settings', label: 'Settings' }
];

/*
 * One app behind the operator's proxy, at an address of its own (specs/122 FR-032): Connect is the checklist and the
 * proxy's configuration, the place an administrator comes back to while wiring it; Access is who may open which
 * path, with a check of what a change would do; Settings is its name, address and deletion.
 */
export function BehindProxyPage({
	bucketId,
	appId,
	tab
}: {
	bucketId: string;
	appId: string;
	tab: BehindProxyTab;
}) {
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [app, setApp] = useState<AppView | null>(null);
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);

	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}`;
	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchAll = useCallback(async () => {
		try {
			const [b, a, g] = await Promise.all([
				request<BucketView>('GET', base),
				request<AppView>('GET', behindProxyApi(bucketId, appId)),
				request<{ groups: GroupView[] }>('GET', groupsApi(bucketId))
			]);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setBucket(b.data);
			// An app deleted while its page was open answers 404 here too, as one that never existed.
			if (!a.ok) {
				setLoadStatus(a.status);
				setLoadMessage(a.error.message);
				return;
			}
			setLoadStatus(null);
			setApp(a.data);
			if (g.ok) setGroups(g.data.groups);
		} finally {
			setLoading(false);
		}
	}, [base, bucketId, appId]);
	useEffect(() => {
		void fetchAll();
	}, [fetchAll]);

	const can = bucketCan(bucket);
	const listHref = bucketHref(bucketId, 'applications');

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="app"
				backHref={bucket ? listHref : '/admin/projects'}
				backLabel={bucket ? 'Back to Applications' : 'Back to Projects'}
			/>
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={() => void fetchAll()}
			/>
		);
	}

	const name = app?.name ?? '…';
	const writable = can.edit && !bucket?.deletion;

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Projects', href: '/admin/projects' },
					{ label: bucket?.name ?? '…', href: bucketHref(bucketId) },
					{ label: 'Applications', href: listHref },
					{ label: name }
				]}
				title={name}
				tags={<Tag>Behind your proxy</Tag>}
				meta={
					app ? (
						<Typography.Text
							code
							copyable={{ text: app.address }}
						>
							{app.address}
						</Typography.Text>
					) : undefined
				}
				tabs={TABS.map((t) => ({
					key: t.key,
					label: t.label,
					href: behindProxyHref(
						bucketId,
						appId,
						t.key === 'connect' ? undefined : t.key
					)
				}))}
				activeTab={tab}
			/>
			{loading && !app && <Skeleton active />}
			{bucket?.deletion && (
				<ScheduledBanner
					bucket={{ ...bucket, deletion: bucket.deletion }}
					canDelete={can.delete}
					onRestored={() => void fetchAll()}
				/>
			)}
			{bucket && !can.edit && !bucket.deletion && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="Only members of the team that owns this project can change this."
				/>
			)}
			{bucket && app && tab === 'connect' && (
				<ConnectTab
					bucketId={bucketId}
					app={app}
					groups={groups}
					onRefresh={() => void fetchAll()}
				/>
			)}
			{bucket && app && tab === 'access' && (
				<AccessTab
					bucketId={bucketId}
					app={app}
					groups={groups}
					writable={writable}
					onChanged={setApp}
				/>
			)}
			{bucket && app && tab === 'settings' && (
				<SettingsTab
					bucketId={bucketId}
					app={app}
					writable={writable}
					onChanged={setApp}
				/>
			)}
		</>
	);
}
