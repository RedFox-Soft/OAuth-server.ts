import { useCallback, useEffect, useState } from 'react';
import { Alert, Skeleton, Tag } from 'antd';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';
import { applicationHref, bucketHref } from '../../frame/routes.js';
import { request } from '../../frame/request.js';
import { bucketCan } from '../../frame/can.js';
import type { BucketView } from '../bucketView.js';
import { ScheduledBanner } from '../ScheduledBanner.js';
import type { ClientRow } from './clientForm.js';
import { describe } from './blocks.js';
import { forgetHandOff, peekHandOff, type HandOff } from './handOff.js';
import { ConnectTab } from './ConnectTab.js';
import { SettingsTab } from './SettingsTab.js';

export type ApplicationTab = 'connect' | 'settings';

const TABS: { key: ApplicationTab; label: string }[] = [
	{ key: 'connect', label: 'Connect' },
	{ key: 'settings', label: 'Settings' }
];

/*
 * One application, at an address of its own (spec 107): Connect is what a developer needs to wire it up and comes
 * back to; Settings is every setting it has, under one save bar. There is no other place an application is edited.
 */
export function ApplicationPage({
	bucketId,
	clientId,
	tab
}: {
	bucketId: string;
	clientId: string;
	tab: ApplicationTab;
}) {
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [client, setClient] = useState<ClientRow | null>(null);
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	// Read at the first render after creation and then forgotten, so a reload finds nothing.
	const [handed, setHanded] = useState<HandOff | undefined>(() =>
		peekHandOff(clientId)
	);
	useEffect(() => {
		forgetHandOff(clientId);
	}, [clientId]);

	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}`;
	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchAll = useCallback(async () => {
		try {
			const [b, c] = await Promise.all([
				request<BucketView>('GET', base),
				request<ClientRow>(
					'GET',
					`${base}/clients/${encodeURIComponent(clientId)}`
				)
			]);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setBucket(b.data);
			// An application deleted while its page was open answers here too: 404, as one that never existed.
			if (!c.ok) {
				setLoadStatus(c.status);
				setLoadMessage(c.error.message);
				return;
			}
			setLoadStatus(null);
			setClient(c.data);
		} finally {
			setLoading(false);
		}
	}, [base, clientId]);
	useEffect(() => {
		void fetchAll();
	}, [fetchAll]);

	const can = bucketCan(bucket);
	const listHref = bucketHref(bucketId, 'applications');

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="application"
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

	const name = client ? client.clientName || client.clientId : '…';
	// A self-registered application is changed only through its own registration access token.
	const writable =
		can.edit && !bucket?.deletion && client?.registeredDynamically !== true;

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
				tags={
					client?.registeredDynamically ? <Tag>Self-registered</Tag> : undefined
				}
				meta={client ? describe(client) : undefined}
				tabs={TABS.map((t) => ({
					key: t.key,
					label: t.label,
					href: applicationHref(
						bucketId,
						clientId,
						t.key === 'settings' ? 'settings' : undefined
					)
				}))}
				activeTab={tab}
			/>
			{loading && !client && <Skeleton active />}
			{bucket?.deletion && (
				<ScheduledBanner
					bucket={{ ...bucket, deletion: bucket.deletion }}
					canDelete={can.delete}
					onRestored={() => void fetchAll()}
				/>
			)}
			{client?.registeredDynamically && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="This application registered itself"
					description="It is read-only here: it is changed through its own registration access token."
				/>
			)}
			{bucket &&
				!can.edit &&
				!bucket.deletion &&
				!client?.registeredDynamically && (
					<Alert
						type="info"
						showIcon
						style={{ marginBottom: 16 }}
						title="Only members of the team that owns this project can change this."
					/>
				)}
			{bucket && client && tab === 'connect' && (
				<ConnectTab
					bucket={bucket}
					client={client}
					writable={writable}
					handed={handed}
					onHandOffUsed={() => setHanded(undefined)}
					onChanged={(next) => setClient(next)}
					onBucketChanged={() => void fetchAll()}
				/>
			)}
			{bucket && client && tab === 'settings' && (
				<SettingsTab
					bucket={bucket}
					client={client}
					writable={writable}
					onChanged={(next) => setClient(next)}
				/>
			)}
		</>
	);
}
