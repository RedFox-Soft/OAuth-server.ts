import { useCallback, useEffect, useState } from 'react';
import { Badge, Tag, Typography, Alert, Skeleton } from 'antd';
import { PageHeader } from '../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../frame/states.js';
import { bucketHref } from '../frame/routes.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useNavigate } from '../frame/router.js';
import { bucketCan, type BucketCan } from '../frame/can.js';
import { reservedOf } from '../../consts.js';
import { useMe } from '../frame/me.js';
import { BucketOverview } from './BucketOverview.js';
import { Clients } from './Clients.js';
import { Resources } from './Resources.js';
import { BucketSettings } from './BucketSettings.js';
import type { BucketSummary, BucketView } from './bucketView.js';
import { FederationPanel } from './FederationPanel.js';
import { BucketKeysPanel } from './BucketKeysPanel.js';
import { BucketActivityPanel } from './BucketActivityPanel.js';
import { BucketNotFound } from './UsageBucketHistory.js';
import { ProvisioningPanel, type ConnectionView } from './ProvisioningPanel.js';
import { BucketGroupsPanel } from './BucketGroupsPanel.js';
import { BucketUsersPanel } from './BucketUsersPanel.js';
import { ScheduledBanner } from './ScheduledBanner.js';
import { SignInTab, signInKey } from './signin/SignInTab.js';

/*
 * Said once, above an area the caller may look at but not change, instead of a page of controls that
 * would each answer 403.
 */
function ReadOnlyNotice() {
	return (
		<Alert
			type="info"
			showIcon
			style={{ marginBottom: 16 }}
			title="Only members of the group that owns this bucket can change this."
		/>
	);
}

/*
 * The bucket's areas, each an address of its own (specs/079); only the one shown loads. The Overview is the
 * bucket's bare address and Settings comes last, with the acts that break things at its foot (specs/081).
 */
export type BucketTab =
	| 'overview'
	| 'applications'
	| 'apis'
	| 'users'
	| 'userGroups'
	| 'signIn'
	| 'providers'
	| 'provisioning'
	| 'keys'
	| 'activity'
	| 'settings';

const TABS: { key: BucketTab; segment?: string; label: string }[] = [
	{ key: 'overview', label: 'Overview' },
	{ key: 'applications', segment: 'applications', label: 'Applications' },
	{ key: 'apis', segment: 'apis', label: 'APIs' },
	{ key: 'users', segment: 'users', label: 'Users' },
	{ key: 'userGroups', segment: 'user-groups', label: 'User groups' },
	{ key: 'signIn', segment: 'sign-in', label: 'Sign-in' },
	{
		key: 'providers',
		segment: 'identity-providers',
		label: 'Identity providers'
	},
	{ key: 'provisioning', segment: 'provisioning', label: 'Provisioning' },
	{ key: 'keys', segment: 'keys', label: 'Signing keys' },
	{ key: 'activity', segment: 'activity', label: 'Activity' },
	{ key: 'settings', segment: 'settings', label: 'Settings' }
];

/* Whether the caller may open an area at all; the others are open to anyone who can read the bucket. */
function tabAllowed(key: BucketTab, can: BucketCan): boolean {
	if (key === 'overview' || key === 'settings' || key === 'signIn') {
		return can.read;
	}
	/*
	 * Read with the bucket's people (`loadBucketForUsers`): closed on the administrators' bucket to everyone,
	 * whose own clients are part of how the server runs and are never managed here.
	 */
	if (key === 'applications' || key === 'apis') return can.manageUsers;
	if (key === 'keys') return can.edit;
	if (key === 'activity') return can.readActivity;
	return true;
}

export function BucketDetail({
	bucketId,
	tab
}: {
	bucketId: string;
	tab: BucketTab;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}`;
	const feedback = useFeedback();
	const navigate = useNavigate();
	const [bucket, setBucket] = useState<BucketView | null>(null);
	// The status a failed read answered, so a missing or foreign bucket is told apart from a fault.
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [connections, setConnections] = useState<ConnectionView[]>([]);
	/*
	 * The two panels below each fetch their own list, and each changes what the other shows: a connection
	 * closes its provider to just-in-time creation, and a provider's state is a connection's warning. A
	 * bumped key is how one tells the other to look again without either holding the other's state.
	 */
	const [federationKey, setFederationKey] = useState(0);
	const [provisioningKey, setProvisioningKey] = useState(0);
	// The counts the Overview, the header's held tag and the delete dialog read (specs/081).
	const [summary, setSummary] = useState<BucketSummary | null>(null);
	const [summaryFailed, setSummaryFailed] = useState(false);
	// Group names for the header and Settings; a group the caller is not in is named generically.
	const [groupNames, setGroupNames] = useState<Map<string, string>>(new Map());
	const { me } = useMe();
	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchBucket = useCallback(async () => {
		try {
			const b = await request<BucketView>('GET', base);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setLoadStatus(null);
			setBucket(b.data);
			const [s, scope] = await Promise.all([
				request<BucketSummary>('GET', `${base}/summary`),
				request<{ available: { id: string; name: string }[] }>(
					'GET',
					'/admin/api/scope'
				)
			]);
			setSummary(s.ok ? s.data : null);
			setSummaryFailed(!s.ok);
			if (scope.ok) {
				setGroupNames(new Map(scope.data.available.map((g) => [g.id, g.name])));
			}
			// The user-groups area names each group's connection; the panel that lists them is not mounted beside it.
			if (tab === 'userGroups') {
				const c = await request<ConnectionView[]>(
					'GET',
					`${base}/provisioning-connections`
				);
				if (c.ok) setConnections(c.data);
				else feedback.failed(c);
			}
		} finally {
			setLoading(false);
		}
	}, [base, tab, feedback]);
	function load() {
		return fetchBucket();
	}
	useEffect(() => {
		void fetchBucket();
	}, [fetchBucket]);

	const can = bucketCan(bucket);
	/*
	 * Which areas open is the server's answer alone. A scheduled bucket is read-only (`can` above), but its keys
	 * stay readable by whoever could manage them — hiding the tab would hide what is about to be destroyed.
	 */
	const granted = bucketCan(bucket ? { can: bucket.can } : null);

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<BucketNotFound bucketId={bucketId} />
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={() => void load()}
			/>
		);
	}

	const shownTab = tab;
	const held = summary !== null && summary.held > 0;
	const tabs = TABS.filter((t) => tabAllowed(t.key, granted)).map((t) => ({
		key: t.key,
		/*
		 * A held directory is marked on the tab that holds it (specs/084 US6), so it is seen from every area of
		 * the bucket, not only from the Overview.
		 */
		label:
			t.key === 'provisioning' && held ? (
				<Badge
					dot
					offset={[6, 0]}
					aria-label="Provisioning, a connection is held"
				>
					{t.label}
				</Badge>
			) : (
				t.label
			),
		href: bucketHref(bucketId, t.segment)
	}));
	const special = bucket ? reservedOf(bucket._id) : null;
	const groupName = bucket
		? (groupNames.get(bucket.ownerGroupId) ?? 'a group you are not in')
		: '';
	/*
	 * An area the caller may not open is said to be so at its own address, rather than quietly showing
	 * Users there: the address keeps meaning what it says, and a link someone shared explains itself.
	 */
	const shownTabLabel = TABS.find((t) => t.key === shownTab)?.label ?? '';
	const tabRefused = bucket !== null && !tabAllowed(shownTab, granted);
	const openSignIn = () => void navigate(bucketHref(bucketId, 'sign-in'));

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Buckets', href: '/admin/buckets' },
					{ label: bucket?.name ?? '…' }
				]}
				title={bucket?.name ?? '…'}
				tags={
					<>
						{special === 'default' && <Tag>Default</Tag>}
						{bucket?.deletion && (
							<Tag color="warning">
								Deletes on{' '}
								{new Date(bucket.deletion.purgeAt).toLocaleDateString()}
							</Tag>
						)}
						{summary && summary.held > 0 && (
							<Tag color="red">Deprovisioning held</Tag>
						)}
					</>
				}
				meta={
					bucket ? (
						<>
							Owned by {groupName}
							{bucket.issuer ? (
								<>
									{' · '}
									<Typography.Text copyable>{bucket.issuer}</Typography.Text>
								</>
							) : null}
						</>
					) : undefined
				}
				description={
					special === 'default'
						? "The instance's own bucket, served at the server's root. Only super administrators manage its applications. It cannot be moved, re-addressed or deleted."
						: undefined
				}
				tabs={tabs}
				activeTab={shownTab}
			/>
			{loading && !bucket && <Skeleton active />}
			{bucket?.deletion && (
				<ScheduledBanner
					bucket={{ ...bucket, deletion: bucket.deletion }}
					canDelete={granted.delete}
					onRestored={() => void load()}
				/>
			)}
			{tabRefused && (
				<NoAccess
					what={`bucket's ${shownTabLabel.toLowerCase()}`}
					backHref={bucketHref(bucketId)}
					backLabel="Go to Overview"
				/>
			)}
			{bucket && !tabRefused && shownTab === 'overview' && (
				<BucketOverview
					bucket={bucket}
					summary={summary}
					summaryFailed={summaryFailed}
					can={can}
					superAdmin={me?.superAdmin === true}
					groupName={groupName}
					onOpenSignIn={openSignIn}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'settings' && (
				<BucketSettings
					bucket={bucket}
					can={can}
					groupName={groupName}
					onChanged={() => void load()}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'signIn' && (
				<SignInTab
					key={signInKey(bucket)}
					bucket={bucket}
					summary={summary}
					summaryFailed={summaryFailed}
					can={can}
					onSaved={() => void load()}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'applications' && (
				<Clients
					bucketId={bucketId}
					writable={can.edit && !bucket.deletion}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'apis' && (
				<Resources
					bucketId={bucketId}
					bucketName={bucket.name}
					canEdit={can.edit && !bucket.deletion}
					superAdmin={me?.superAdmin === true}
				/>
			)}
			{/* A scheduled bucket's banner already says why nothing can be changed. */}
			{bucket && !tabRefused && !bucket.deletion && (
				<>
					{shownTab === 'users' && !can.manageUsers && <ReadOnlyNotice />}
					{(shownTab === 'userGroups' ||
						shownTab === 'providers' ||
						shownTab === 'provisioning') &&
						!can.edit && <ReadOnlyNotice />}
				</>
			)}
			{bucket && !tabRefused && shownTab === 'users' && (
				<BucketUsersPanel
					bucketId={bucketId}
					can={can}
					mailConfigured={summary?.mailDeliveryConfigured}
					passwordLogin={bucket.passwordLogin}
				/>
			)}

			{/*
			 * Mounted only once the bucket is known: each panel fetches on mount, and a bucket the caller cannot
			 * read should answer once, with the page's refusal, not once per panel.
			 */}
			{bucket && shownTab === 'userGroups' && (
				<BucketGroupsPanel
					bucketId={bucketId}
					can={can}
					connections={connections}
					onChanged={() => void load()}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'providers' && (
				<FederationPanel
					key={federationKey}
					bucket={bucket}
					canEdit={can.edit}
					onChanged={() => {
						void load();
						setProvisioningKey((k) => k + 1);
					}}
				/>
			)}
			{bucket && shownTab === 'provisioning' && (
				<ProvisioningPanel
					bucket={bucket}
					canEdit={can.edit}
					refreshKey={provisioningKey}
					onConnections={setConnections}
					onChanged={() => {
						void load();
						setFederationKey((k) => k + 1);
					}}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'keys' && (
				<BucketKeysPanel
					bucket={bucket}
					canEdit={can.edit}
					superAdmin={me?.superAdmin === true}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'activity' && (
				<BucketActivityPanel
					bucketId={bucketId}
					usageLink={me?.superAdmin === true}
				/>
			)}
		</>
	);
}
