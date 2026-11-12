import { useCallback, useEffect, useState } from 'react';
import { Alert, Skeleton, Tag, Typography } from 'antd';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';
import { apiHref, bucketHref } from '../../frame/routes.js';
import { request } from '../../frame/request.js';
import { bucketCan } from '../../frame/can.js';
import { useMe } from '../../frame/me.js';
import type { BucketView } from '../bucketView.js';
import { ScheduledBanner } from '../ScheduledBanner.js';
import { groupsApi, type GroupView } from '../groups/groupShared.js';
import { resourcesApi, type ResourceView } from './resourceView.js';
import { ApiConnectTab } from './ApiConnectTab.js';
import { ApiAccessTab } from './ApiAccessTab.js';
import { ApiSettingsTab } from './ApiSettingsTab.js';

export type ApiTab = 'connect' | 'access' | 'settings';

const TABS: { key: ApiTab; label: string }[] = [
	{ key: 'connect', label: 'Connect' },
	{ key: 'access', label: 'Access' },
	{ key: 'settings', label: 'Settings' }
];

/*
 * One API declared in a project (specs/132), built like an app behind the proxy: Connect is what the proxy or the API
 * must do, the place an administrator comes back to while wiring it; Access is who may call it and what each tool
 * needs, with the check of those rules under them; Settings is what describes the API and its tokens, and removal.
 */
export function ApiPage({
	bucketId,
	identifier,
	tab
}: {
	bucketId: string;
	identifier: string;
	tab: ApiTab;
}) {
	const { me } = useMe();
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [api, setApi] = useState<ResourceView | null>(null);
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchAll = useCallback(async () => {
		try {
			const [b, a, g] = await Promise.all([
				request<BucketView>(
					'GET',
					`/admin/api/projects/${encodeURIComponent(bucketId)}`
				),
				request<ResourceView>('GET', resourcesApi(bucketId, identifier)),
				request<{ groups: GroupView[] }>('GET', groupsApi(bucketId))
			]);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setBucket(b.data);
			// An API removed while its page was open answers 404 here too, as one that never existed.
			if (!a.ok) {
				setLoadStatus(a.status);
				setLoadMessage(a.error.message);
				return;
			}
			setLoadStatus(null);
			setApi(a.data);
			if (g.ok) setGroups(g.data.groups);
		} finally {
			setLoading(false);
		}
	}, [bucketId, identifier]);
	useEffect(() => {
		void fetchAll();
	}, [fetchAll]);

	const can = bucketCan(bucket);
	const listHref = bucketHref(bucketId, 'apis');

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="API"
				backHref={bucket ? listHref : '/admin/projects'}
				backLabel={bucket ? 'Back to APIs' : 'Back to Projects'}
			/>
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={() => void fetchAll()}
			/>
		);
	}

	/*
	 * A project with no address of its own declares in the instance's shared root namespace, where only a super
	 * administrator writes (lib/resources/namespace.ts). The server refuses anyone else the same way; this only keeps
	 * the page from offering what it would refuse.
	 */
	const rootNamespace =
		bucket?.addressForm === 'root' || bucket?.addressForm === 'unaddressed';
	const superAdmin = me?.superAdmin === true;
	const writable =
		can.edit && !bucket?.deletion && (!rootNamespace || superAdmin);
	const name = api?.name ?? '…';

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Projects', href: '/admin/projects' },
					{ label: bucket?.name ?? '…', href: bucketHref(bucketId) },
					{ label: 'APIs', href: listHref },
					{ label: name }
				]}
				title={name}
				tags={
					api ? (
						<Tag>
							{api.checkedBy === 'proxy'
								? 'Checked by your proxy'
								: 'Checked by your server'}
						</Tag>
					) : undefined
				}
				meta={
					<Typography.Text
						code
						copyable={{ text: identifier }}
					>
						{identifier}
					</Typography.Text>
				}
				tabs={TABS.map((t) => ({
					key: t.key,
					label: t.label,
					href: apiHref(
						bucketId,
						identifier,
						t.key === 'connect' ? undefined : t.key
					)
				}))}
				activeTab={tab}
			/>
			{loading && !api && <Skeleton active />}
			{bucket?.deletion && (
				<ScheduledBanner
					bucket={{ ...bucket, deletion: bucket.deletion }}
					canDelete={can.delete}
					onRestored={() => void fetchAll()}
				/>
			)}
			{bucket && !bucket.deletion && !writable && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title={
						can.edit
							? "This project has no address of its own, so its APIs live in the instance's root namespace, where only a super administrator can declare or change them."
							: "Changing a project's APIs takes membership of the team that owns it."
					}
				/>
			)}
			{bucket && api && tab === 'connect' && (
				<ApiConnectTab
					bucketId={bucketId}
					api={api}
					writable={writable}
					onRefresh={() => void fetchAll()}
				/>
			)}
			{bucket && api && tab === 'access' && (
				<ApiAccessTab
					bucketId={bucketId}
					api={api}
					groups={groups}
					writable={writable}
					onChanged={() => void fetchAll()}
				/>
			)}
			{bucket && api && tab === 'settings' && (
				<ApiSettingsTab
					bucketId={bucketId}
					api={api}
					writable={writable}
					onChanged={() => void fetchAll()}
				/>
			)}
		</>
	);
}
