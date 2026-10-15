import { useCallback, useEffect, useState } from 'react';
import { Flex, Skeleton } from 'antd';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed } from '../../frame/states.js';
import { Link } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { bucketCan } from '../../frame/can.js';
import { ADMIN_BUCKET_ID } from '../../../consts.js';
import type { BucketSummary, BucketView } from '../bucketView.js';
import { SignInTab, signInKey } from '../signin/SignInTab.js';
import { FederationPanel } from '../FederationPanel.js';
import { BucketActivityPanel } from '../BucketActivityPanel.js';
import { GeneralCard } from '../BucketSettings.js';
import { Admins } from '../Admins.js';

export type AdministratorsTab =
	'accounts' | 'signIn' | 'providers' | 'activity' | 'settings';

const TABS: { key: AdministratorsTab; segment?: string; label: string }[] = [
	{ key: 'accounts', label: 'Accounts' },
	{ key: 'signIn', segment: 'sign-in', label: 'Sign-in' },
	{
		key: 'providers',
		segment: 'identity-providers',
		label: 'Identity providers'
	},
	{ key: 'activity', segment: 'activity', label: 'Activity' },
	{ key: 'settings', segment: 'settings', label: 'Settings' }
];

const tabHref = (segment?: string) =>
	segment ? `/admin/administrators/${segment}` : '/admin/administrators';

/*
 * The console's own bucket, at home with its accounts (specs/083). It used to be a bucket page with most of
 * its tabs hidden, five clicks from the list of the people it signs in; now the people, how they sign in,
 * who vouches for them, how often they come, and the bucket's name are one page. Only super administrators
 * reach it — the route table refuses everyone else before this renders.
 */
export function AdministratorsHome({ tab }: { tab: AdministratorsTab }) {
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [summary, setSummary] = useState<BucketSummary | null>(null);
	const [summaryFailed, setSummaryFailed] = useState(false);
	const [failed, setFailed] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const base = `/admin/api/projects/${ADMIN_BUCKET_ID}`;

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchBucket = useCallback(async () => {
		try {
			const [b, s] = await Promise.all([
				request<BucketView>('GET', base),
				request<BucketSummary>('GET', `${base}/summary`)
			]);
			if (!b.ok) {
				setFailed(b.error.message);
				return;
			}
			setFailed(null);
			setBucket(b.data);
			setSummary(s.ok ? s.data : null);
			setSummaryFailed(!s.ok);
		} finally {
			setLoading(false);
		}
	}, [base]);
	useEffect(() => {
		void fetchBucket();
	}, [fetchBucket]);
	const reload = () => void fetchBucket();
	const can = bucketCan(bucket);

	const body = () => {
		if (tab === 'accounts') {
			return (
				<Admins
					verificationRequired={bucket?.emailVerificationRequired === true}
				/>
			);
		}
		if (failed !== null) {
			return (
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			);
		}
		if (!bucket) return loading ? <Skeleton active /> : null;
		switch (tab) {
			case 'signIn':
				return (
					<SignInTab
						key={signInKey(bucket)}
						bucket={bucket}
						summary={summary}
						summaryFailed={summaryFailed}
						can={can}
						consoleBucket
						onSaved={reload}
					/>
				);
			case 'providers':
				return (
					<FederationPanel
						bucket={bucket}
						consoleBucket
						canEdit={can.editSettings}
						onChanged={reload}
					/>
				);
			case 'activity':
				return (
					<Flex
						vertical
						gap={12}
					>
						<BucketActivityPanel
							bucketId={ADMIN_BUCKET_ID}
							usageLink
						/>
						{/* Changes to an administrator's account are recorded against the account, not a bucket. */}
						<Link href="/admin/audit?targetType=AdminUser">
							Changes to administrators are in Audit →
						</Link>
					</Flex>
				);
			case 'settings':
				return (
					<GeneralCard
						bucket={bucket}
						canEdit={can.editSettings}
						onChanged={reload}
					/>
				);
		}
	};

	return (
		<>
			<PageHeader
				title="Administrators"
				description="The people who run this instance, and how they sign in to the console."
				tabs={TABS.map((t) => ({
					key: t.key,
					label: t.label,
					href: tabHref(t.segment)
				}))}
				activeTab={tab}
			/>
			{body()}
		</>
	);
}
